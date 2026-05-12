package com.safelink.ui.history

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import com.safelink.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun ScanDetailScreen(scanId: Long, onBack: () -> Unit) {
    val context = LocalContext.current
    var record by remember { mutableStateOf<ScanRecord?>(null) }

    LaunchedEffect(scanId) {
        val r = withContext(Dispatchers.IO) {
            SafeLinkDatabase.getInstance(context).scanDao().getById(scanId)
        }
        record = r
    }

    record?.let { r ->
        val statusColor = when (r.verdict) {
            "SAFE" -> Primary
            "WARNING" -> Tertiary
            else -> Error
        }

        val statusIcon = when (r.verdict) {
            "SAFE" -> Icons.Default.CheckCircle
            "WARNING" -> Icons.Default.Warning
            else -> Icons.Default.Error
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Background)
                .verticalScroll(rememberScrollState())
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                IconButton(
                    onClick = onBack,
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(SurfaceContainerHigh)
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                }
                
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = Primary, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "SafeLink",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                }
                
                Box(modifier = Modifier.size(48.dp)) // Spacer
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Large Icon
                Box(contentAlignment = Alignment.Center) {
                    Surface(
                        modifier = Modifier.size(120.dp),
                        shape = CircleShape,
                        color = statusColor.copy(alpha = 0.1f)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(statusIcon, contentDescription = null, tint = statusColor, modifier = Modifier.size(64.dp))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                Surface(
                    shape = CircleShape,
                    color = statusColor.copy(alpha = 0.1f),
                    border = CardDefaults.outlinedCardBorder(true).copy(width = 1.dp)
                ) {
                    Text(
                        text = r.verdict,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                        color = statusColor,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 2.sp
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = if (r.verdict == "SAFE") "No threats detected" else "Potential Threat Detected",
                    style = MaterialTheme.typography.titleMedium,
                    color = OnSurfaceVariant
                )
            }

            // Info Card
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp),
                shape = RoundedCornerShape(32.dp),
                color = SurfaceContainerLow
            ) {
                Column(modifier = Modifier.padding(24.dp)) {
                    Text(
                        text = "TARGETED URL",
                        style = MaterialTheme.typography.labelSmall,
                        color = OnSurfaceVariant,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 2.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = r.url,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(SurfaceContainerHigh, RoundedCornerShape(16.dp))
                            .padding(16.dp)
                    )
                    
                    Spacer(modifier = Modifier.height(24.dp))
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        DetailLabelValue("Layer", r.layer)
                        DetailLabelValue("Confidence", "${(r.confidence * 100).toInt()}%")
                    }
                }
            }

            if (r.primaryReason.isNotBlank()) {
                SectionHeader("Why Flagged")
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    shape = RoundedCornerShape(24.dp),
                    color = SurfaceContainer
                ) {
                    Row(modifier = Modifier.padding(20.dp), verticalAlignment = Alignment.Top) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .background(SurfaceContainerHigh, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("1", fontWeight = FontWeight.Bold, color = Primary)
                        }
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(
                            text = r.primaryReason,
                            style = MaterialTheme.typography.bodyMedium,
                            color = OnSurfaceVariant,
                            lineHeight = 22.sp
                        )
                    }
                }
            }

            if (r.geminiExplanation.isNotBlank()) {
                SectionHeader("AI Analysis")
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    shape = RoundedCornerShape(32.dp),
                    color = Primary.copy(alpha = 0.05f)
                ) {
                    Column(modifier = Modifier.padding(24.dp)) {
                        Text(
                            text = "\"${r.geminiExplanation}\"",
                            style = MaterialTheme.typography.bodyLarge,
                            fontStyle = androidx.compose.ui.text.font.FontStyle.Italic,
                            lineHeight = 26.sp
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(modifier = Modifier.size(8.dp).background(Primary, CircleShape))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "SafeLink Guard AI",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Black,
                                color = Primary,
                                letterSpacing = 1.sp
                            )
                        }
                    }
                }
            }

            SectionHeader("Technical Scores")
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp),
                shape = RoundedCornerShape(32.dp),
                color = SurfaceContainerLow
            ) {
                Column(modifier = Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    ScoreRow("CNN Analysis", r.cnnScore)
                    ScoreRow("Semantic Scan", r.bertScore)
                    ScoreRow("Anomaly MSE", r.anomalyScore, isMse = true)
                }
            }
            
            Spacer(modifier = Modifier.height(40.dp))
        }
    }
}

@Composable
fun DetailLabelValue(label: String, value: String) {
    Column {
        Text(text = label.uppercase(), style = MaterialTheme.typography.labelSmall, color = OnSurfaceVariant, fontWeight = FontWeight.Black, letterSpacing = 1.sp)
        Text(text = value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = OnSurface)
    }
}

@Composable
fun SectionHeader(title: String) {
    Text(
        text = title,
        modifier = Modifier.padding(start = 32.dp, top = 32.dp, bottom = 12.dp),
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold
    )
}

@Composable
fun ScoreRow(label: String, score: Float, isMse: Boolean = false) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Bottom) {
            Text(text = label.uppercase(), style = MaterialTheme.typography.labelSmall, color = OnSurfaceVariant, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            Text(
                text = if (isMse) String.format("%.4f", score) else "${(score * 100).toInt()}%",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Black,
                color = Primary
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        LinearProgressIndicator(
            progress = if (isMse) (score * 10).coerceIn(0f, 1f) else score,
            modifier = Modifier.fillMaxWidth().height(8.dp).clip(CircleShape),
            color = Primary,
            trackColor = SurfaceContainerHigh
        )
    }
}
