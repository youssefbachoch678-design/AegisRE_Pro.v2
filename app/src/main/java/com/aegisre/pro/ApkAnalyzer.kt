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
    val warning: String? = null
)

object ApkAnalyzer {
    private const val MAX_FILE_BYTES = 300L * 1024 * 1024
    private const val MAX_EXPANDED_BYTES = 100L * 1024 * 1024
    private const val MAX_ENTRIES = 10_000

    fun analyze(resolver: ContentResolver, uri: Uri): AnalysisResult {
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: "Selected APK"
        return try {
            var dex = 0
            var native = 0
            var assets = 0
            var entries = 0
            var expanded = 0L
            resolver.openInputStream(uri)?.use { raw ->
                val zip = ZipInputStream(raw)
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val entry = zip.nextEntry ?: break
                    entries++
                    require(entries <= MAX_ENTRIES) { "Too many ZIP entries" }
                    if (entry.name.matches(Regex("classes(\\d*)\\.dex"))) dex++
                    if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) native++
                    if (entry.name.startsWith("assets/")) assets++
                    while (true) {
                        val count = zip.read(buffer)
                        if (count < 0) break
                        expanded += count
                        require(expanded <= MAX_EXPANDED_BYTES) { "Expanded data limit exceeded" }
                    }
                    zip.closeEntry()
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
                    require(fileBytes <= MAX_FILE_BYTES) { "APK file-size limit exceeded" }
                    digest.update(buffer, 0, count)
                }
            } ?: error("Cannot reopen file for hashing")

            AnalysisResult(
                fileName = name,
                sha256 = digest.digest().joinToString("") { "%02x".format(it) },
                dexFiles = dex,
                nativeLibraries = native,
                assetFiles = assets,
                totalEntries = entries
            )
        } catch (error: Exception) {
            AnalysisResult(name, "", 0, 0, 0, 0, error.message ?: "Analysis failed")
        }
    }
}
