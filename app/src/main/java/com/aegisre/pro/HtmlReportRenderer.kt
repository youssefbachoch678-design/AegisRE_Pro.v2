package com.aegisre.pro

object HtmlReportRenderer {
    fun render(result: AnalysisResult): String {
        fun esc(value: String): String = value
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")
        val findings = result.securityFindings.joinToString("") { finding ->
            "<article><h3>${esc(finding.title)} <small>${esc(finding.severity.name)}</small></h3>" +
                "<p><b>Confidence:</b> ${esc(finding.confidence)}</p>" +
                "<p><b>Evidence:</b> ${esc(finding.evidence)}</p>" +
                "<p>${esc(finding.explanation)}</p><p><b>Remediation:</b> ${esc(finding.remediation)}</p></article>"
        }
        val permissions = result.manifest?.usesPermissions.orEmpty().joinToString("") { "<li>${esc(it)}</li>" }
        val certs = result.certificates.joinToString("") {
            "<li>${esc(it.path)} — ${esc(it.subject)} — SHA-256: ${esc(it.sha256)}</li>"
        }
        val dex = result.dexDetails.joinToString("") {
            "<li>${esc(it.fileName)}: DEX ${esc(it.version)}, ${it.classCount} classes, ${it.methodCount} method references</li>"
        }
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>AegisRE report - ${esc(result.fileName)}</title>
<style>
body{font:15px system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 18px;background:#101722;color:#e8eef7}
h1,h2{color:#69d6c7}article{border:1px solid #354458;border-radius:8px;padding:12px;margin:12px 0}
small{color:#ffb0a8}code{overflow-wrap:anywhere}li{margin:5px 0}.muted{color:#aab7c8}
</style></head><body>
<h1>AegisRE Pro — Static APK Analysis</h1>
<p class="muted">Offline report. Findings are heuristic indicators and require manual review; absence of findings is not proof of safety.</p>
<h2>Package</h2><p><b>File:</b> ${esc(result.fileName)}</p><p><b>SHA-256:</b> <code>${esc(result.sha256)}</code></p>
<p>DEX: ${result.dexFiles} · Native libraries: ${result.nativeLibraries} · Assets: ${result.assetFiles} · ZIP entries: ${result.totalEntries}</p>
<h2>Security findings (${result.securityFindings.size})</h2>${findings.ifEmpty { "<p>No matches in the current limited ruleset.</p>" }}
<h2>Manifest permissions</h2><ul>${permissions}</ul>
<h2>DEX summary</h2><ul>${dex}</ul>
<h2>Signing certificate candidates</h2><ul>${certs}</ul>
<p class="muted">Certificate metadata from META-INF entries is not equivalent to APK v2/v3 signature verification. Generated locally by AegisRE Pro.</p>
</body></html>"""
    }
}
