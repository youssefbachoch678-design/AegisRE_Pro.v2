package com.aegisre.pro

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class ManifestSummary(
    val packageName: String?,
    val versionName: String?,
    val usesPermissions: List<String>,
    val declaredComponents: List<String>,
    val isBinaryXml: Boolean
)

data class ElfSummary(
    val path: String,
    val bitness: String,
    val endianness: String,
    val machine: String,
    val fileType: String
)

object ApkMetadataReader {
    fun inspectManifest(bytes: ByteArray): ManifestSummary {
        val text = bytes.toString(Charsets.UTF_8)
        if (!text.trimStart().startsWith("<?xml") && !text.trimStart().startsWith("<manifest")) {
            return ManifestSummary(null, null, emptyList(), emptyList(), true)
        }
        fun attr(tag: String, name: String): String? {
            val tagMatch = Regex("<$tag\\b[^>]*>", RegexOption.IGNORE_CASE).find(text)?.value ?: return null
            return Regex("(?:android:)?$name\\s*=\\s*[\"']([^\"']*)[\"']", RegexOption.IGNORE_CASE)
                .find(tagMatch)?.groupValues?.get(1)
        }
        val packageName = attr("manifest", "package")
        val versionName = attr("manifest", "versionName")
        val permissions = Regex("<uses-permission(?:-sdk-\\d+)?\\b[^>]*android:name\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE)
            .findAll(text).map { it.groupValues[1] }.distinct().take(200).toList()
        val components = Regex("<(activity|activity-alias|service|receiver|provider)\\b[^>]*android:name\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE)
            .findAll(text).map { "${it.groupValues[1]}: ${it.groupValues[2]}" }.distinct().take(200).toList()
        return ManifestSummary(packageName, versionName, permissions, components, false)
    }

    fun inspectElf(path: String, bytes: ByteArray): ElfSummary? {
        if (bytes.size < 20 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) return null
        val bitness = when (bytes[4].toInt() and 0xff) { 1 -> "32-bit"; 2 -> "64-bit"; else -> "Unknown" }
        val endian = when (bytes[5].toInt() and 0xff) { 1 -> "Little-endian"; 2 -> "Big-endian"; else -> return null }
        val order = if (endian == "Little-endian") ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val b = ByteBuffer.wrap(bytes).order(order)
        val type = when (b.getShort(16).toInt() and 0xffff) {
            1 -> "Relocatable"; 2 -> "Executable"; 3 -> "Shared object"; 4 -> "Core"; else -> "Other"
        }
        val machine = when (b.getShort(18).toInt() and 0xffff) {
            3 -> "x86"; 40 -> "ARM"; 62 -> "x86-64"; 183 -> "AArch64"; 243 -> "RISC-V"; else -> "Unknown"
        }
        return ElfSummary(path, bitness, endian, machine, type)
    }
}
