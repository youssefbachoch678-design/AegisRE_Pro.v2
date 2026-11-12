package com.aegisre.pro

import android.content.ContentResolver
import android.net.Uri
import java.security.MessageDigest
import java.util.zip.ZipInputStream

data class AnalysisResult(
    val fileName: String,
    val sha256: String,
    val dexFiles: Int,
    val nativeLibraries: Int,
    val assetFiles: Int,
    val totalEntries: Int,
    val abiCounts: Map<String, Int> = emptyMap(),
    val entryNames: List<String> = emptyList(),
    val warning: String? = null
)

object ApkAnalyzer {
    private const val MAX_FILE_BYTES = 300L * 1024 * 1024
    private const val MAX_EXPANDED_BYTES = 100L * 1024 * 1024
    private const val MAX_ENTRIES = 10_000
    private const val MAX_RECORDED_NAMES = 2_000

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

            resolver.openInputStream(uri)?.use { raw ->
                ZipInputStream(raw).use { zip ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        val entry = zip.nextEntry ?: break
                        entries++
                        require(entries <= MAX_ENTRIES) { "Too many ZIP entries (limit: $MAX_ENTRIES)" }
                        val path = entry.name
                        if (entryNames.size < MAX_RECORDED_NAMES) entryNames += path
                        if (path.matches(Regex("classes(\\d*)\\.dex"))) dex++
                        if (path.startsWith("assets/")) assets++
                        val parts = path.split('/')
                        if (parts.size >= 3 && parts[0] == "lib" && parts.last().endsWith(".so")) {
                            native++
                            val abi = parts[1]
                            abiCounts[abi] = (abiCounts[abi] ?: 0) + 1
                        }
                        while (true) {
                            val count = zip.read(buffer)
                            if (count < 0) break
                            expanded += count
                            require(expanded <= MAX_EXPANDED_BYTES) { "Expanded data limit exceeded (100 MB safety limit)" }
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
                entryNames = entryNames
            )
        } catch (error: Exception) {
            AnalysisResult(name, "", 0, 0, 0, 0, warning = error.message ?: "Analysis failed")
        }
    }
}
