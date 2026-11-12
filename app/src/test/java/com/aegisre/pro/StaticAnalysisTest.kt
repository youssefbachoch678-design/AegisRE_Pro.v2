package com.aegisre.pro

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StaticAnalysisTest {
    @Test fun parsesPlaintextManifestPermissionsAndFlags() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
            <manifest package="org.example.demo" android:versionName="1.2">
              <uses-permission android:name="android.permission.CAMERA"/>
              <application android:debuggable="true" android:usesCleartextTraffic="true">
                <activity android:name=".MainActivity" android:exported="true"/>
              </application>
            </manifest>""".trimIndent()
        val result = ApkMetadataReader.inspectManifest(xml.toByteArray())
        assertEquals("org.example.demo", result.packageName)
        assertTrue(result.usesPermissions.contains("android.permission.CAMERA"))
        assertEquals(true, result.debuggable)
        assertEquals(true, result.cleartextTrafficPermitted)
        assertEquals(true, result.components.single().exported)
    }

    @Test fun flagsRiskyManifestSettingsWithEvidence() {
        val manifest = ManifestSummary(
            "org.example.demo", "1", emptyList(), emptyList(), false,
            cleartextTrafficPermitted = true,
            debuggable = true
        )
        val findings = SecurityRulesEngine.scan(manifest, emptyList())
        assertTrue(findings.any { it.id == "MANIFEST:CLEARTEXT" && it.evidence.isNotBlank() })
        assertTrue(findings.any { it.id == "MANIFEST:DEBUGGABLE" })
    }

    @Test fun stringMatchesAreReviewRequiredAndDoNotExposeSecret() {
        val findings = SecurityRulesEngine.scan(null, listOf("api_key=AbCdEfGhIjKlMnOpQrSt"))
        val finding = findings.single { it.id == "STRINGS:POSSIBLE_SECRET" }
        assertEquals("REVIEW_REQUIRED", finding.confidence)
        assertFalse(finding.evidence.contains("AbCdEfGhIjKlMnOpQrSt"))
    }

    @Test fun rejectsNonElfAndTruncatedElfHeaders() {
        assertEquals(null, ApkMetadataReader.inspectElf("libfake.so", byteArrayOf(1, 2, 3, 4)))
        val truncated = ByteArray(20)
        byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1).forEachIndexed { index, value ->
            truncated[index] = value.toByte()
        }
        assertEquals(null, ApkMetadataReader.inspectElf("libtruncated.so", truncated))
    }

    @Test fun acceptsWellFormedMinimalElf64Header() {
        val bytes = ByteArray(64)
        byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1).forEachIndexed { index, value ->
            bytes[index] = value.toByte()
        }
        bytes[16] = 3
        bytes[18] = 62
        bytes[20] = 1
        bytes[52] = 64
        val result = ApkMetadataReader.inspectElf("libvalid.so", bytes)
        assertEquals("64-bit", result?.bitness)
        assertEquals("x86-64", result?.machine)
        assertEquals("Shared object", result?.fileType)
    }

    @Test fun rejectsBinaryXmlWithInvalidHeaderSize() {
        val bytes = ByteArray(8)
        bytes[0] = 3
        bytes[1] = 0
        bytes[2] = 0
        bytes[3] = 0
        bytes[4] = 8
        assertTrue(runCatching { BinaryXmlReader.read(bytes) }.isFailure)
    }

    @Test fun decodesDexModifiedUtf8IncludingEncodedNull() {
        val bytes = minimalDexWithString(byteArrayOf(0x41, 0xc0.toByte(), 0x80.toByte(), 0x42, 0))
        val result = DexTableReader.inspect(bytes)
        assertEquals(listOf("A\u0000B"), result.stringSamples)
        assertEquals(null, result.warning)
    }

    @Test fun rejectsDexTablesOutsideDeclaredFileSize() {
        val bytes = minimalDexWithString(byteArrayOf(0x41, 0x42, 0x43, 0))
        putU32(bytes, 32, 112)
        val result = DexTableReader.inspect(bytes)
        assertTrue(result.warning?.contains("outside file") == true)
    }

    @Test fun inspectsZipLikeFileAndComputesSha256() {
        val info = FileInspector.inspect("demo.apk", byteArrayOf(0x50, 0x4b, 0x03, 0x04))
        assertEquals("ZIP archive / APK container", info.detectedType)
        assertEquals(64, info.sha256.length)
    }

    @Test fun detectsUnclosedOpeningDelimiter() {
        val diagnostics = CodeDiagnostics.checkDelimiters("""fun main() {
 println(1)
""")
        assertTrue(diagnostics.any { it.message.contains("no matching close") })
    }

    @Test fun ignoresDelimitersInsideStringAndComments() {
        val source = """val text = "{[()]}" // }
/* { */"""
        assertTrue(CodeDiagnostics.checkDelimiters(source).isEmpty())
    }

    private fun minimalDexWithString(encoded: ByteArray): ByteArray {
        val dataOffset = 116
        val bytes = ByteArray(dataOffset + 1 + encoded.size)
        bytes[0] = 'd'.code.toByte()
        bytes[1] = 'e'.code.toByte()
        bytes[2] = 'x'.code.toByte()
        bytes[3] = 10
        bytes[7] = 0
        putU32(bytes, 32, bytes.size)
        putU32(bytes, 36, 112)
        putU32(bytes, 40, 0x12345678)
        putU32(bytes, 56, 1)
        putU32(bytes, 60, 112)
        putU32(bytes, 112, dataOffset)
        bytes[dataOffset] = 3
        encoded.copyInto(bytes, dataOffset + 1)
        return bytes
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        for (i in 0 until 4) bytes[offset + i] = (value ushr (i * 8)).toByte()
    }
}
