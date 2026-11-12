package com.aegisre.pro

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.io.ByteArrayInputStream

data class ManifestComponent(
    val type: String,
    val name: String,
    val exported: Boolean?,
    val permission: String?
)

data class ManifestSummary(
    val packageName: String?,
    val versionName: String?,
    val usesPermissions: List<String>,
    val declaredComponents: List<String>,
    val isBinaryXml: Boolean,
    val cleartextTrafficPermitted: Boolean? = null,
    val debuggable: Boolean? = null,
    val allowBackup: Boolean? = null,
    val hasNetworkSecurityConfig: Boolean = false,
    val components: List<ManifestComponent> = emptyList()
)

data class CertificateSummary(\n    val path: String,\n    val subject: String,\n    val issuer: String,\n    val validFrom: String,\n    val validUntil: String,\n    val sha256: String\n)\n\ndata class ElfSummary(
    val path: String,
    val bitness: String,
    val endianness: String,
    val machine: String,
    val fileType: String
)

object ApkMetadataReader {
    fun inspectManifest(bytes: ByteArray): ManifestSummary {
        if (bytes.size >= 2 && bytes[0] == 0x03.toByte() && bytes[1] == 0x00.toByte()) {
            return try {
                val elements = BinaryXmlReader.read(bytes)
                val manifest = elements.firstOrNull { it.name == "manifest" }?.attributes.orEmpty()
                val app = elements.firstOrNull { it.name == "application" }?.attributes.orEmpty()
                val permissions = elements.filter { it.name.startsWith("uses-permission") }
                    .mapNotNull { it.attributes["name"] }.distinct().take(300)
                val componentTypes = setOf("activity", "activity-alias", "service", "receiver", "provider")
                val components = elements.filter { it.name in componentTypes }.mapNotNull { e ->
                    val name = e.attributes["name"] ?: return@mapNotNull null
                    ManifestComponent(e.name, name, e.attributes["exported"]?.toBooleanStrictOrNull(), e.attributes["permission"])
                }.take(300)
                ManifestSummary(manifest["package"], manifest["versionName"], permissions,
                    components.map { "${it.type}: ${it.name}" }.distinct(), true,
                    app["usesCleartextTraffic"]?.toBooleanStrictOrNull(),
                    app["debuggable"]?.toBooleanStrictOrNull(),
                    app["allowBackup"]?.toBooleanStrictOrNull(),
                    app.containsKey("networkSecurityConfig"), components)
            } catch (_: Exception) {
                ManifestSummary(null, null, emptyList(), emptyList(), true)
            }
        }
        val text = bytes.toString(Charsets.UTF_8)
        if (!text.trimStart().startsWith("<?xml") && !text.trimStart().startsWith("<manifest")) {
            return ManifestSummary(null, null, emptyList(), emptyList(), true)
        }
        fun tagText(tag: String): String? =
            Regex("<$tag\\b[^>]*>", RegexOption.IGNORE_CASE).find(text)?.value

        fun attr(tag: String, name: String): String? {
            val source = tagText(tag) ?: return null
            return Regex("(?:android:)?$name\\s*=\\s*[\"']([^\"']*)[\"']", RegexOption.IGNORE_CASE)
                .find(source)?.groupValues?.get(1)
        }

        val permissions = Regex("<uses-permission(?:-sdk-\\d+)?\\b[^>]*android:name\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE)
            .findAll(text).map { it.groupValues[1] }.distinct().take(300).toList()

        val components = mutableListOf<ManifestComponent>()
        val componentRegex = Regex("<(activity|activity-alias|service|receiver|provider)\\b([^>]*)>", RegexOption.IGNORE_CASE)
        componentRegex.findAll(text).take(300).forEach { match ->
            val type = match.groupValues[1]
            val attrs = match.groupValues[2]
            fun componentAttr(name: String): String? =
                Regex("(?:android:)?$name\\s*=\\s*[\"']([^\"']*)[\"']", RegexOption.IGNORE_CASE)
                    .find(attrs)?.groupValues?.get(1)
            val name = componentAttr("name") ?: return@forEach
            val exported = componentAttr("exported")?.let { it.equals("true", true) }
            components += ManifestComponent(type, name, exported, componentAttr("permission"))
        }

        return ManifestSummary(
            packageName = attr("manifest", "package"),
            versionName = attr("manifest", "versionName"),
            usesPermissions = permissions,
            declaredComponents = components.map { "${it.type}: ${it.name}" }.distinct(),
            isBinaryXml = false,
            cleartextTrafficPermitted = attr("application", "usesCleartextTraffic")?.let { it.equals("true", true) },
            debuggable = attr("application", "debuggable")?.let { it.equals("true", true) },
            allowBackup = attr("application", "allowBackup")?.let { it.equals("true", true) },
            hasNetworkSecurityConfig = attr("application", "networkSecurityConfig") != null,
            components = components
        )
    }

    fun inspectCertificates(path: String, bytes: ByteArray): List<CertificateSummary> {
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            factory.generateCertificates(ByteArrayInputStream(bytes)).filterIsInstance<X509Certificate>()
                .take(10).map { cert ->
                    CertificateSummary(
                        path,
                        cert.subjectX500Principal.name,
                        cert.issuerX500Principal.name,
                        cert.notBefore.toInstant().toString(),
                        cert.notAfter.toInstant().toString(),
                        MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                            .joinToString("") { "%02X".format(it) }
                    )
                }
        } catch (_: Exception) {
            emptyList()
        }
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
