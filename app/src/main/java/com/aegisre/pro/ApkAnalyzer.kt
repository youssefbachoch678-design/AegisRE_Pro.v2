package com.aegisre.pro

import android.content.ContentResolver
import android.net.Uri
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

data class DexInfo(
    val fileName: String,
    val version: String,
    val fileSize: Long,
    val stringCount: Long,
    val typeCount: Long,
    val methodCount: Long,
    val classCount: Long
)

data class AnalysisResult(
    val fileName: String,
    val sha256: String,
    val dexFiles: Int,
    val nativeLibraries: Int,
    val assetFiles: Int,
    val totalEntries: Int,
    val abiCounts: Map<String, Int> = emptyMap(),
    val entryNames: List<String> = emptyList(),
    val dexDetails: List<DexInfo> = emptyList(),
    val dexBrowse: List<DexBrowseResult> = emptyList(),
    val manifest: ManifestSummary? = null,
    val elfFiles: List<ElfSummary> = emptyList(),
    val xmlResourcePaths: List<String> = emptyList(),
    val warning: String? = null
)

object ApkAnalyzer {
    private const val MAX_FILE_BYTES = 300L * 1024 * 1024
    private const val MAX_EXPANDED_BYTES = 100L * 1024 * 1024
    private const val MAX_ENTRIES = 10_000
    private const val MAX_RECORDED_NAMES = 2_000
    private const val DEX_HEADER_SIZE = 112
    private const val MAX_DEX_PARSE_BYTES = 24 * 1024 * 1024

    fun analyze(resolver: ContentResolver, uri: Uri): AnalysisResult {
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: "Selected APK"
        return try {
            var dex = 0
            var native = 0
            var assets = 0
            var entries = 0
            var expanded = 0L
            val abiCounts = linkedMapOf<String, Int>()
            val entryNames = mutableListOf<String>()
            val dexDetails = mutableListOf<DexInfo>()
            val dexBrowse = mutableListOf<DexBrowseResult>()
            var manifestSummary: ManifestSummary? = null
            val elfFiles = mutableListOf<ElfSummary>()
            val xmlResourcePaths = mutableListOf<String>()

            resolver.openInputStream(uri)?.use { raw ->
                ZipInputStream(raw).use { zip ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        val entry = zip.nextEntry ?: break
                        entries++
                        require(entries <= MAX_ENTRIES) { "Too many ZIP entries (limit: $MAX_ENTRIES)" }
                        val path = entry.name
                        if (entryNames.size < MAX_RECORDED_NAMES) entryNames += path
                        val isDex = path.matches(Regex("classes(\\d*)\\.dex"))
                        if (isDex) dex++
                        if (path.startsWith("assets/")) assets++
                        val parts = path.split('/')
                        if (parts.size >= 3 && parts[0] == "lib" && parts.last().endsWith(".so")) {
                            native++
                            val abi = parts[1]
                            abiCounts[abi] = (abiCounts[abi] ?: 0) + 1
                        }

                        val header = ByteArray(DEX_HEADER_SIZE)
                        var headerBytes = 0
                        val dexBuffer = if (isDex) ByteArrayOutputStream() else null
                        val metadataBuffer = if (path == "AndroidManifest.xml" || (path.startsWith("res/") && path.endsWith(".xml")) || path.endsWith(".so")) ByteArrayOutputStream() else null
                        var dexTooLarge = false
                        while (true) {
                            val count = zip.read(buffer)
                            if (count < 0) break
                            expanded += count
                            require(expanded <= MAX_EXPANDED_BYTES) { "Expanded data limit exceeded (100 MB safety limit)" }
                            if (metadataBuffer != null && metadataBuffer.size() < 1024 * 1024) {
                                val keep = minOf(count, 1024 * 1024 - metadataBuffer.size())
                                if (keep > 0) metadataBuffer.write(buffer, 0, keep)
                            }
                            if (isDex && !dexTooLarge && dexBuffer != null) {
                                if (dexBuffer.size().toLong() + count <= MAX_DEX_PARSE_BYTES) dexBuffer.write(buffer, 0, count)
                                else dexTooLarge = true
                            }
                            if (isDex && headerBytes < DEX_HEADER_SIZE) {
                                val copyCount = minOf(count, DEX_HEADER_SIZE - headerBytes)
                                buffer.copyInto(header, headerBytes, 0, copyCount)
                                headerBytes += copyCount
                            }
                        }
                        if (path == "AndroidManifest.xml" && metadataBuffer != null) manifestSummary = ApkMetadataReader.inspectManifest(metadataBuffer.toByteArray())
                        if (path.startsWith("res/") && path.endsWith(".xml") && xmlResourcePaths.size < 500) xmlResourcePaths += path
                        if (path.endsWith(".so") && metadataBuffer != null) ApkMetadataReader.inspectElf(path, metadataBuffer.toByteArray())?.let(elfFiles::add)
                        if (isDex && headerBytes == DEX_HEADER_SIZE) {
                            parseDexHeader(path, header)?.let(dexDetails::add)
                            if (!dexTooLarge && dexBuffer != null) dexBrowse += DexTableReader.inspect(dexBuffer.toByteArray())
                            else dexBrowse += DexBrowseResult(emptyList(), emptyList(), emptyList(), "DEX exceeds the 24 MB per-file inspection limit")
                        }
                        zip.closeEntry()
                    }
                }
            } ?: error("Cannot open selected file")

            val digest = MessageDigest.getInstance("SHA-256")
            var fileBytes = 0L
            resolver.openInputStream(uri)?.use { input ->
                val buffer = ByteArray(32 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    fileBytes += count
                    require(fileBytes <= MAX_FILE_BYTES) { "APK file-size limit exceeded (300 MB)" }
                    digest.update(buffer, 0, count)
                }
            } ?: error("Cannot reopen file for hashing")

            AnalysisResult(
                fileName = name,
                sha256 = digest.digest().joinToString("") { "%02x".format(it) },
                dexFiles = dex,
                nativeLibraries = native,
                assetFiles = assets,
                totalEntries = entries,
                abiCounts = abiCounts.toSortedMap(),
                entryNames = entryNames,
                dexDetails = dexDetails,
                dexBrowse = dexBrowse,
                manifest = manifestSummary,
                elfFiles = elfFiles.take(200),
                xmlResourcePaths = xmlResourcePaths
            )
        } catch (error: Exception) {
            AnalysisResult(name, "", 0, 0, 0, 0, warning = error.message ?: "Analysis failed")
        }
    }

    private fun parseDexHeader(path: String, header: ByteArray): DexInfo? {
        if (header[0] != 'd'.code.toByte() ||
            header[1] != 'e'.code.toByte() ||
            header[2] != 'x'.code.toByte() ||
            header[3] != 10.toByte() ||
            header[7] != 0.toByte()
        ) return null

        val version = header.copyOfRange(4, 7).toString(Charsets.US_ASCII)
        val data = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val headerSize = data.getInt(36).toLong() and 0xffffffffL
        val endianTag = data.getInt(40).toLong() and 0xffffffffL
        if (headerSize != DEX_HEADER_SIZE.toLong() || endianTag != 0x12345678L) return null

        return DexInfo(
            fileName = path,
            version = version,
            fileSize = data.getInt(32).toLong() and 0xffffffffL,
            stringCount = data.getInt(56).toLong() and 0xffffffffL,
            typeCount = data.getInt(64).toLong() and 0xffffffffL,
            methodCount = data.getInt(88).toLong() and 0xffffffffL,
            classCount = data.getInt(96).toLong() and 0xffffffffL
        )
    }
}
