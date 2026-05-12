package com.safelink.ui.home

import android.content.Intent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.gson.Gson
import com.safelink.App
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import com.safelink.ml.Verdict
import com.safelink.network.NetworkChecker
import com.safelink.service.SafeLinkPredictor
import com.safelink.ui.BrowserUtils
import com.safelink.ui.NoInternetPopupActivity
import com.safelink.ui.VerdictComposeActivity
import com.safelink.ui.components.SignatureGradient
import com.safelink.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var searchUrl by remember { mutableStateOf("") }
    var isScanning by remember { mutableStateOf(false) }
    var scanCount by remember { mutableStateOf(0) }
    var lastVerdict by remember { mutableStateOf<String?>(null) }
    var protectionEnabled by remember { mutableStateOf(App.protectionEnabled) }

    LaunchedEffect(Unit) {
        val count = withContext(Dispatchers.IO) {
            SafeLinkDatabase.getInstance(context).scanDao().count()
        }
        scanCount = count
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Background)
            .padding(bottom = 80.dp) // Space for bottom nav
    ) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "SafeLink",
                style = MaterialTheme.typography.headlineMedium,
                color = OnSurface,
                fontWeight = FontWeight.Bold
            )
            IconButton(
                onClick = {
                    protectionEnabled = !protectionEnabled
                    App.protectionEnabled = protectionEnabled
                    context.getSharedPreferences("safelink_prefs", android.content.Context.MODE_PRIVATE)
                        .edit().putBoolean("protection_enabled", protectionEnabled).apply()
                },
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .background(SurfaceContainerHigh)
            ) {
                Icon(
                    Icons.Default.Shield,
                    contentDescription = "Shield",
                    tint = if (protectionEnabled) Primary else OnSurfaceVariant
                )
            }
        }

        // Hero Section
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(contentAlignment = Alignment.Center) {
                // Halo Background
                Box(
                    modifier = Modifier
                        .size(256.dp)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(
                                    (if (protectionEnabled) PrimaryContainer else OnSurfaceVariant).copy(alpha = 0.15f),
                                    Color.Transparent
                                )
                            ),
                            CircleShape
                        )
                )

                // Animated Shield
                val infiniteTransition = rememberInfiniteTransition(label = "shield")
                val translateY by infiniteTransition.animateFloat(
                    initialValue = 0f,
                    targetValue = if (protectionEnabled) -10f else 0f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(2000, easing = EaseInOut),
                        repeatMode = RepeatMode.Reverse
                    ),
                    label = "translateY"
                )

                Surface(
                    modifier = Modifier
                        .size(192.dp)
                        .offset(y = translateY.dp),
                    shape = CircleShape,
                    color = SurfaceContainer,
                    tonalElevation = 8.dp,
                    border = CardDefaults.outlinedCardBorder(true).copy(width = 0.5.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Default.Shield,
                            contentDescription = null,
                            modifier = Modifier.size(80.dp),
                            tint = if (protectionEnabled) PrimaryContainer else OnSurfaceVariant
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(40.dp))
            Text(
                text = if (protectionEnabled) "Protection Active" else "Protection Paused",
                style = MaterialTheme.typography.headlineLarge.copy(fontSize = 32.sp),
                color = OnSurface,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = if (protectionEnabled) "Device is secured in real-time" else "Your device is not being scanned",
                color = OnSurfaceVariant,
                style = MaterialTheme.typography.bodyLarge
            )
        }

        // Status Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceContainerLow)
        ) {
            Column(modifier = Modifier.padding(24.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(if (lastVerdict != null) {
                                when(lastVerdict) {
                                    "SAFE" -> Primary
                                    "WARNING" -> Tertiary
                                    else -> Error
                                }
                            } else PrimaryContainer)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "STATUS",
                        style = MaterialTheme.typography.labelSmall,
                        color = OnSurfaceVariant,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 2.sp
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = if (lastVerdict != null) "Last scan: $lastVerdict" 
                           else if (scanCount == 0) "No links scanned yet" 
                           else "$scanCount links scanned",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = if (lastVerdict != null) "Just now" else "Protection is active",
                    color = OnSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Scan Actions
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
        ) {
            TextField(
                value = searchUrl,
                onValueChange = { searchUrl = it },
                placeholder = { Text("Paste a link to check") },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp)
                    .clip(RoundedCornerShape(16.dp)),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = SurfaceContainerHigh,
                    unfocusedContainerColor = SurfaceContainerHigh,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent
                )
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    if (searchUrl.isNotBlank() && !isScanning) {
                        isScanning = true
                        val rawUrl = searchUrl.trim()
                        val url = if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) rawUrl
                                 else "https://$rawUrl"
                        
                        scope.launch {
                            val predictor = SafeLinkPredictor(
                                networkChecker = NetworkChecker(context),
                                geminiClient = App.geminiClient,
                                dynamicWhitelist = App.dynamicWhitelist,
                            )

                            val result = withContext(Dispatchers.IO) { predictor.predict(url) }

                            withContext(Dispatchers.IO) {
                                SafeLinkDatabase.getInstance(context).scanDao().insert(
                                    ScanRecord(
                                        url = url,
                                        verdict = result.verdict.name,
                                        confidence = result.confidence,
                                        primaryReason = result.primaryReason,
                                        allReasons = Gson().toJson(result.allReasons),
                                        geminiExplanation = result.geminiExplanation,
                                        cnnScore = result.cnnScore,
                                        bertScore = result.bertScore,
                                        anomalyScore = result.anomalyMse,
                                        domainAgeDays = result.domainAgeDays,
                                        layer = result.layer,
                                    )
                                )
                                // Update local scan count
                                val newCount = SafeLinkDatabase.getInstance(context).scanDao().count()
                                scanCount = newCount
                            }

                            lastVerdict = result.verdict.name
                            isScanning = false
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                contentPadding = PaddingValues()
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(SignatureGradient),
                    contentAlignment = Alignment.Center
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Bolt, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isScanning) "Scanning..." else "Scan Now",
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp
                        )
                    }
                }
            }
        }
    }
}
