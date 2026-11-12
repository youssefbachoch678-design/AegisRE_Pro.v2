package com.aegisre.pro

enum class FindingSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

data class SecurityFinding(
    val id: String,
    val title: String,
    val severity: FindingSeverity,
    val confidence: String,
    val evidence: String,
    val explanation: String,
    val remediation: String
)

object SecurityRulesEngine {
    private val sensitivePermissions = mapOf(
        "android.permission.READ_SMS" to ("HIGH" to "Allows reading SMS messages, which may contain private data."),
        "android.permission.RECEIVE_SMS" to ("HIGH" to "Allows receiving SMS broadcasts."),
        "android.permission.SEND_SMS" to ("HIGH" to "Allows sending SMS messages."),
        "android.permission.READ_CONTACTS" to ("MEDIUM" to "Allows access to the user's contacts."),
        "android.permission.WRITE_CONTACTS" to ("MEDIUM" to "Allows modifying the user's contacts."),
        "android.permission.RECORD_AUDIO" to ("HIGH" to "Allows microphone access."),
        "android.permission.CAMERA" to ("MEDIUM" to "Allows camera access."),
        "android.permission.ACCESS_FINE_LOCATION" to ("HIGH" to "Allows precise location access."),
        "android.permission.ACCESS_COARSE_LOCATION" to ("MEDIUM" to "Allows approximate location access."),
        "android.permission.READ_CALL_LOG" to ("HIGH" to "Allows reading call history."),
        "android.permission.READ_PHONE_STATE" to ("MEDIUM" to "Allows access to phone-state information.")
    )

    fun scan(manifest: ManifestSummary?, strings: List<String>): List<SecurityFinding> {
        val findings = mutableListOf<SecurityFinding>()
        if (manifest != null) {
            manifest.usesPermissions.distinct().forEach { permission ->
                val rule = sensitivePermissions[permission] ?: return@forEach
                findings += SecurityFinding(
                    id = "PERMISSION:$permission",
                    title = "Sensitive permission declared",
                    severity = if (rule.first == "HIGH") FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                    confidence = "CONFIRMED_DECLARATION",
                    evidence = permission,
                    explanation = rule.second,
                    remediation = "Remove the permission if it is not essential. If required, request it only when needed and explain its use to the user."
                )
            }
            if (manifest.cleartextTrafficPermitted == true) {
                findings += SecurityFinding(
                    id = "MANIFEST:CLEARTEXT",
                    title = "Cleartext traffic is explicitly permitted",
                    severity = FindingSeverity.HIGH,
                    confidence = "CONFIRMED_CONFIGURATION",
                    evidence = "android:usesCleartextTraffic=\"true\"",
                    explanation = "The application configuration permits HTTP traffic that may be observed or modified on an untrusted network.",
                    remediation = "Set usesCleartextTraffic to false and use HTTPS endpoints. If exceptions are necessary, restrict them with a Network Security Config."
                )
            }
            if (manifest.debuggable == true) {
                findings += SecurityFinding(
                    id = "MANIFEST:DEBUGGABLE",
                    title = "Debuggable application build",
                    severity = FindingSeverity.MEDIUM,
                    confidence = "CONFIRMED_CONFIGURATION",
                    evidence = "android:debuggable=\"true\"",
                    explanation = "Debuggable builds expose debugging capabilities that should normally not be enabled in production.",
                    remediation = "Disable debuggable in release builds and verify the final release manifest."
                )
            }
            manifest.components.filter { it.exported == true }.forEach { component ->
                findings += SecurityFinding(
                    id = "COMPONENT:${component.type}:${component.name}",
                    title = "Exported Android component",
                    severity = FindingSeverity.MEDIUM,
                    confidence = "CONFIRMED_EXPORTED_FLAG",
                    evidence = "${component.type} ${component.name} declares android:exported=true",
                    explanation = "Other apps may be able to address this component. Exported components are not automatically vulnerable; access controls and intent handling determine the actual risk.",
                    remediation = "Set exported=false when external access is unnecessary. Otherwise enforce permissions and validate all incoming intents and data."
                )
            }
            if (manifest.hasNetworkSecurityConfig) {
                findings += SecurityFinding(
                    id = "MANIFEST:NETWORK_CONFIG",
                    title = "Network Security Config is referenced",
                    severity = FindingSeverity.INFO,
                    confidence = "CONFIRMED_REFERENCE",
                    evidence = "android:networkSecurityConfig is present in the application tag",
                    explanation = "A configuration file is referenced, but its contents are not yet parsed by this version.",
                    remediation = "Review the referenced XML for cleartext exceptions, trusted user certificates, and unintended trust anchors."
                )
            }
            if (manifest.allowBackup == true) {
                findings += SecurityFinding(
                    id = "MANIFEST:BACKUP",
                    title = "Application backup is enabled",
                    severity = FindingSeverity.LOW,
                    confidence = "CONFIRMED_CONFIGURATION",
                    evidence = "android:allowBackup=\"true\"",
                    explanation = "Application data may be included in device backup depending on Android version and backup rules.",
                    remediation = "Review backup contents and exclude sensitive data using appropriate backup rules; disable backup if it is not needed."
                )
            }
        }

        val httpUrl = strings.firstOrNull { Regex("http://[A-Za-z0-9.-]+").containsMatchIn(it) }
        if (httpUrl != null) findings += SecurityFinding(
            id = "STRINGS:HTTP_URL",
            title = "HTTP endpoint string detected",
            severity = FindingSeverity.MEDIUM,
            confidence = "REVIEW_REQUIRED",
            evidence = "A string containing an http:// URL was found in inspected DEX data; URL value is hidden.",
            explanation = "An HTTP URL may indicate unencrypted transport, but it could also be a test value or an upgrade/redirect endpoint.",
            remediation = "Verify the endpoint and switch application data traffic to HTTPS. Confirm that no sensitive information is sent over HTTP."
        )

        val secretPatterns = listOf(
            Regex("(?i)(api[_-]?key|client[_-]?secret|access[_-]?token)\\s*[:=]\\s*['\"]?[A-Za-z0-9_./+=-]{12,}"),
            Regex("AIza[0-9A-Za-z_-]{30,}"),
            Regex("(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
        )
        if (strings.any { value -> secretPatterns.any { it.containsMatchIn(value) } }) {
            findings += SecurityFinding(
                id = "STRINGS:POSSIBLE_SECRET",
                title = "Possible embedded secret",
                severity = FindingSeverity.HIGH,
                confidence = "REVIEW_REQUIRED",
                evidence = "A DEX string matched a common API-key, token, or private-key pattern; matched content is not displayed.",
                explanation = "Hard-coded credentials can be extracted from an APK. Pattern matches may be false positives or public identifiers.",
                remediation = "Confirm the match without sharing the value. Revoke exposed credentials, move secrets to a trusted backend, and avoid embedding private keys in the client."
            )
        }

        return findings.distinctBy { it.id }.sortedWith(
            compareBy<SecurityFinding> { it.severity.ordinal }.thenBy { it.title }
        )
    }
}
