package com.aegisre.pro

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Bg = Color(0xFF0B1018)
private val Panel = Color(0xFF151E2B)
private val Panel2 = Color(0xFF1C2938)
private val Accent = Color(0xFF69D6C7)
private val Muted = Color(0xFF91A1B5)
private val MainText = Color(0xFFE7EDF5)
private val Amber = Color(0xFFE6B86A)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AegisWorkbench() }
    }
}

@Composable
private fun AegisWorkbench() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var results by remember { mutableStateOf<List<AnalysisResult>>(emptyList()) }
    var selected by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("WORKSPACE READY · STATIC MODE") }
    var pathQuery by remember { mutableStateOf("") }
    var pendingReport by remember { mutableStateOf("") }
    val reportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/html")) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { it.write(pendingReport.toByteArray(Charsets.UTF_8)) }
            }
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris: List<Uri> ->
        val chosen = uris.take(50)
        results = emptyList()
        selected = 0
        status = "${chosen.size} FILE(S) SELECTED"
        if (chosen.isNotEmpty()) {
            busy = true
            scope.launch {
                results = withContext(Dispatchers.IO) { chosen.map { ApkAnalyzer.analyze(context.contentResolver, it) } }
                busy = false
                status = "ANALYSIS COMPLETE · LOCAL ONLY"
            }
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(background = Bg, surface = Panel, primary = Accent, onBackground = MainText, onSurface = MainText)) {
        Column(Modifier.fillMaxSize().background(Bg)) {
            Row(Modifier.fillMaxWidth().background(Panel).padding(horizontal = 16.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                Image(painter = painterResource(R.drawable.ic_launcher_foreground), contentDescription = "AegisRE shield gear logo", modifier = Modifier.size(36.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text("AEGISRE PRO", color = MainText, fontWeight = FontWeight.Black, fontSize = 17.sp)
                    Text("ANDROID RESEARCH WORKBENCH", color = Muted, fontSize = 9.sp, letterSpacing = 1.4.sp)
                }
                Text(status, color = Accent, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
            }
            Row(Modifier.fillMaxWidth().weight(1f).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(Modifier.width(155.dp).fillMaxHeight().background(Panel, RoundedCornerShape(8.dp)).padding(10.dp)) {
                    Text("PROJECT", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(12.dp))
                    Text("▾ WORKSPACE", color = MainText, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    Text("  APK SAMPLES", color = Muted, fontSize = 10.sp)
                    Spacer(Modifier.height(14.dp))
                    Button(onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, enabled = !busy, modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(4.dp), colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Bg)) {
                        Icon(Icons.Default.FolderOpen, null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Open APK", fontSize = 10.sp)
                    }
                    Spacer(Modifier.height(12.dp))
                    Text("LOADED FILES · ${results.size}", color = Muted, fontSize = 9.sp)
                    LazyColumn {
                        items(results.indices.toList()) { index ->
                            Text(
                                results[index].fileName,
                                Modifier.fillMaxWidth()
                                    .background(if (selected == index) Panel2 else Color.Transparent, RoundedCornerShape(4.dp))
                                    .clickable { selected = index; pathQuery = "" }
                                    .padding(6.dp),
                                color = if (selected == index) Accent else MainText,
                                fontSize = 10.sp,
                                maxLines = 2
                            )
                        }
                    }
                }
                Column(Modifier.weight(1.15f).fillMaxHeight().background(Panel, RoundedCornerShape(8.dp)).verticalScroll(rememberScrollState()).padding(12.dp)) {
                    Text("ANALYSIS OVERVIEW", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(10.dp))
                    if (busy) {
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = Accent)
                        Text("Inspecting package structure…", color = Muted, fontSize = 11.sp)
                    } else if (results.isEmpty()) {
                        Text("No APK loaded", color = MainText, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                        Text("Open an APK to populate the workspace.", color = Muted, fontSize = 12.sp)
                    } else {
                        val result = results.getOrNull(selected)
                        if (result != null) {
                            Text(result.fileName, color = MainText, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                            Button(
                                onClick = {
                                    pendingReport = HtmlReportRenderer.render(result)
                                    reportLauncher.launch(result.fileName.substringBeforeLast('.', result.fileName) + "-aegisre-report.html")
                                },
                                modifier = Modifier.fillMaxWidth(),
                                contentPadding = PaddingValues(6.dp)
                            ) { Text("Export HTML report", fontSize = 10.sp) }
                            Spacer(Modifier.height(10.dp))
                            if (result.warning != null) Text(result.warning, color = Amber, fontSize = 11.sp) else {
                                WorkMetric("DEX modules", result.dexFiles.toString())
                                WorkMetric("Native libraries", result.nativeLibraries.toString())
                                WorkMetric("Assets", result.assetFiles.toString())
                                WorkMetric("ZIP entries", result.totalEntries.toString())
                                Spacer(Modifier.height(12.dp))
                                Text("DEX HEADER SUMMARY", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                if (result.dexDetails.isEmpty()) {
                                    Text("No valid standard DEX headers found.", color = Muted, fontSize = 10.sp)
                                }
                                result.dexDetails.forEach { dexInfo ->
                                    Text(dexInfo.fileName, color = MainText, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                    WorkMetric("  DEX version", dexInfo.version)
                                    WorkMetric("  Classes", dexInfo.classCount.toString())
                                    WorkMetric("  Methods", dexInfo.methodCount.toString())
                                    WorkMetric("  Types / strings", "${dexInfo.typeCount} / ${dexInfo.stringCount}")
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("DEX EXPLORER · FIRST 500 ITEMS", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                result.dexBrowse.forEachIndexed { dexIndex, browse ->
                                    Text("DEX #${dexIndex + 1}", color = MainText, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    browse.warning?.let { Text(it, color = Amber, fontSize = 9.sp) }
                                    Text("CLASSES · ${browse.classNames.size}", color = Muted, fontSize = 9.sp)
                                    browse.classNames.take(80).forEach { item ->
                                        Text(item, color = MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
                                    }
                                    Text("METHOD REFERENCES · ${browse.methodNames.size}", color = Muted, fontSize = 9.sp)
                                    browse.methodNames.take(80).forEach { item ->
                                        Text(item, color = Accent, fontSize = 9.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
                                    }
                                    Text("STRING SAMPLES · ${browse.stringSamples.size}", color = Muted, fontSize = 9.sp)
                                    browse.stringSamples.take(40).forEach { item ->
                                        Text(item, color = MainText, fontSize = 9.sp, maxLines = 1)
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("MANIFEST INSPECTOR", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                val manifest = result.manifest
                                if (manifest == null) Text("AndroidManifest.xml not found", color = Muted, fontSize = 10.sp)
                                else {
                                    if (manifest.isBinaryXml) Text("Binary AndroidManifest decoded · attributes may omit resource-resolved values", color = Amber, fontSize = 10.sp)
                                    WorkMetric("Package", manifest.packageName ?: "Unknown")
                                    WorkMetric("Version", manifest.versionName ?: "Unknown")
                                    Text("PERMISSIONS · ${manifest.usesPermissions.size}", color = Muted, fontSize = 9.sp)
                                    manifest.usesPermissions.take(30).forEach { Text(it, color = MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace) }
                                    Text("COMPONENTS · ${manifest.declaredComponents.size}", color = Muted, fontSize = 9.sp)
                                    manifest.declaredComponents.take(30).forEach { Text(it, color = MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace) }
                                    WorkMetric("Cleartext permitted", manifest.cleartextTrafficPermitted?.toString() ?: "Not specified")
                                    WorkMetric("Debuggable", manifest.debuggable?.toString() ?: "Not specified")
                                    WorkMetric("Backup enabled", manifest.allowBackup?.toString() ?: "Not specified")
                                    WorkMetric("Network config", if (manifest.hasNetworkSecurityConfig) "Referenced · content not parsed" else "Not referenced")
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("SECURITY FINDINGS · ${result.securityFindings.size}", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                if (result.securityFindings.isEmpty()) {
                                    Text("No matches from the current limited ruleset. This is not proof that the APK is secure.", color = Muted, fontSize = 10.sp)
                                }
                                result.securityFindings.forEach { finding ->
                                    val severityColor = when (finding.severity) {
                                        FindingSeverity.CRITICAL, FindingSeverity.HIGH -> Color(0xFFFF7777)
                                        FindingSeverity.MEDIUM -> Amber
                                        FindingSeverity.LOW -> Accent
                                        FindingSeverity.INFO -> Muted
                                    }
                                    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).background(Panel2, RoundedCornerShape(6.dp)).padding(8.dp)) {
                                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text(finding.title, color = MainText, fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                                            Text(finding.severity.name, color = severityColor, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                        }
                                        Text("Confidence: ${finding.confidence}", color = Muted, fontSize = 9.sp)
                                        Text("Evidence: ${finding.evidence}", color = MainText, fontSize = 9.sp)
                                        Text(finding.explanation, color = Muted, fontSize = 9.sp)
                                        Text("Fix: ${finding.remediation}", color = Accent, fontSize = 9.sp)
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("NATIVE ELF INSPECTOR · ${result.elfFiles.size}", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                result.elfFiles.take(50).forEach { elf ->
                                    Text(elf.path, color = MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                                    WorkMetric("Format", "${elf.bitness} · ${elf.machine}")
                                    WorkMetric("ELF", "${elf.fileType} · ${elf.endianness}")
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("SIGNING CERTIFICATES · ${result.certificates.size}", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                if (result.certificates.isEmpty()) Text("No v1 META-INF certificate candidate found. APK v2/v3 signing-block verification is not implemented.", color = Muted, fontSize = 9.sp)
                                result.certificates.forEach { cert ->
                                    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
                                        Text(cert.path, color = MainText, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                        Text("Subject: ${cert.subject}", color = Muted, fontSize = 9.sp)
                                        Text("Issuer: ${cert.issuer}", color = Muted, fontSize = 9.sp)
                                        Text("Valid: ${cert.validFrom} → ${cert.validUntil}", color = Muted, fontSize = 9.sp)
                                        Text("Certificate SHA-256: ${cert.sha256}", color = Accent, fontSize = 8.sp, fontFamily = FontFamily.Monospace)
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("XML RESOURCE FILES · ${result.xmlResourcePaths.size}", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                result.xmlResourcePaths.take(50).forEach { Text(it, color = MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace) }
                                Spacer(Modifier.height(12.dp))
                                Text("NATIVE ABI TARGETS", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                if (result.abiCounts.isEmpty()) Text("No .so libraries detected", color = Muted, fontSize = 11.sp)
                                result.abiCounts.forEach { (abi, count) -> WorkMetric(abi, "$count libraries") }
                                Spacer(Modifier.height(12.dp))
                                Text("SHA-256", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                Text(result.sha256, color = Muted, fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
                Column(Modifier.weight(1f).fillMaxHeight().background(Panel, RoundedCornerShape(8.dp)).padding(10.dp)) {
                    val result = results.getOrNull(selected)
                    Text("PROGRAM TREE / ZIP CONTENTS", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    if (result == null) Text("File paths appear here after analysis.", color = Muted, fontSize = 11.sp) else {
                        Text("${result.entryNames.size} paths recorded · up to 2,000", color = Muted, fontSize = 9.sp)
                        OutlinedTextField(value = pathQuery, onValueChange = { pathQuery = it }, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Search paths", fontSize = 10.sp) })
                        val visiblePaths = result.entryNames.filter { it.contains(pathQuery, ignoreCase = true) }
                        Text("${visiblePaths.size} matches", color = Muted, fontSize = 9.sp)
                        LazyColumn(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            items(visiblePaths) { path ->
                                Text("› $path", color = if (path.endsWith(".dex") || path.endsWith(".so")) Accent else MainText, fontSize = 9.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
                            }
                        }
                    }
                }
            }
            Row(Modifier.fillMaxWidth().background(Panel).padding(horizontal = 12.dp, vertical = 5.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("AEGISRE · STATIC INSPECTION ONLY", color = Muted, fontSize = 9.sp)
                Text(if (busy) "BUSY" else "READY", color = Accent, fontSize = 9.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun WorkMetric(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Muted, fontSize = 11.sp)
        Text(value, color = MainText, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
    }
}
