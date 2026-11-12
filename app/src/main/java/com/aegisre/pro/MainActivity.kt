package com.aegisre.pro

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val BackgroundTop = Color(0xFF080D18)
private val BackgroundBottom = Color(0xFF05070D)
private val Panel = Color(0xFF141F30)
private val Accent = Color(0xFF61D5C8)
private val Muted = Color(0xFF9AA9BD)
private val Warning = Color(0xFFFFC078)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AegisHome() }
    }
}

@Composable
private fun AegisHome() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var results by remember { mutableStateOf<List<AnalysisResult>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Ready for authorized static inspection") }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        val chosen = uris.take(50)
        status = if (uris.size > 50) "50-file limit applied" else "${chosen.size} file(s) selected"
        results = emptyList()
        if (chosen.isNotEmpty()) {
            busy = true
            scope.launch {
                results = withContext(Dispatchers.IO) {
                    chosen.map { ApkAnalyzer.analyze(context.contentResolver, it) }
                }
                busy = false
                status = "Analysis complete"
            }
        }
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            background = BackgroundBottom, surface = Panel, primary = Accent,
            onBackground = Color.White, onSurface = Color.White
        )
    ) {
        Scaffold(containerColor = Color.Transparent) { padding ->
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Brush.verticalGradient(listOf(BackgroundTop, BackgroundBottom)))
                    .padding(padding),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = Accent, modifier = Modifier.size(38.dp))
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text("AEGISRE PRO", fontSize = 24.sp, fontWeight = FontWeight.Black, color = Color.White)
                            Text("STATIC APK INTELLIGENCE", fontSize = 11.sp, color = Muted, letterSpacing = 1.8.sp)
                        }
                    }
                }
                item {
                    Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(24.dp)).padding(20.dp)) {
                        Text("Inspect. Understand. Verify.", fontSize = 21.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Inspect APK structure, DEX files, native libraries and CPU architectures without installing or executing the package.",
                            color = Muted, fontSize = 14.sp, lineHeight = 21.sp
                        )
                        Spacer(Modifier.height(18.dp))
                        Button(
                            onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = BackgroundBottom)
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Choose APK files", fontWeight = FontWeight.Bold)
                        }
                        Spacer(Modifier.height(12.dp))
                        Text(status, color = Muted, fontSize = 12.sp)
                        if (busy) {
                            Spacer(Modifier.height(10.dp))
                            LinearProgressIndicator(Modifier.fillMaxWidth(), color = Accent)
                        }
                    }
                }
                items(results) { result ->
                    Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(20.dp)).padding(18.dp)) {
                        Text(result.fileName, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                        Spacer(Modifier.height(12.dp))
                        if (result.warning != null) {
                            Text("Could not analyze: ${result.warning}", color = Warning, fontSize = 13.sp)
                        } else {
                            Metric("DEX files", result.dexFiles.toString())
                            Metric("Native libraries", result.nativeLibraries.toString())
                            Metric("Asset files", result.assetFiles.toString())
                            Metric("Total ZIP entries", result.totalEntries.toString())
                            Spacer(Modifier.height(12.dp))
                            Text("NATIVE CPU ARCHITECTURES", color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                            if (result.abiCounts.isEmpty()) {
                                Text("No native .so libraries found", color = Muted, fontSize = 12.sp)
                            } else {
                                result.abiCounts.forEach { (abi, count) -> Metric(abi, "$count libraries") }
                            }
                            Spacer(Modifier.height(12.dp))
                            Text("SHA-256", color = Accent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Text(result.sha256, color = Muted, fontSize = 11.sp, lineHeight = 17.sp)
                            Spacer(Modifier.height(14.dp))
                            Text("FILE INVENTORY · ${result.entryNames.size} recorded", color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.height(6.dp))
                            result.entryNames.take(40).forEach { path ->
                                Text(path, color = Muted, fontSize = 10.sp, lineHeight = 14.sp)
                            }
                            if (result.entryNames.size > 40) {
                                Text("…and ${result.entryNames.size - 40} more recorded paths", color = Muted, fontSize = 10.sp)
                            }
                        }
                    }
                }
                item {
                    Text(
                        "Preliminary static indicators only — not a definitive malware verdict. APK files are analyzed locally and are not uploaded.",
                        color = Muted, fontSize = 11.sp, lineHeight = 17.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Muted, fontSize = 13.sp)
        Text(value, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
    }
}
