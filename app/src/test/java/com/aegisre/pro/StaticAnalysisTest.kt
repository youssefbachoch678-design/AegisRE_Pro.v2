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

    @Test fun rejectsNonElfInput() {
        assertEquals(null, ApkMetadataReader.inspectElf("libfake.so", byteArrayOf(1, 2, 3, 4)))
    }
}
