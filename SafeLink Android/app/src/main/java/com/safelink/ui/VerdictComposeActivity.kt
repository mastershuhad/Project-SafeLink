package com.safelink.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.safelink.ui.theme.*

class VerdictComposeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val url = intent.getStringExtra("url") ?: ""
        val verdict = intent.getStringExtra("verdict") ?: "WARNING"
        val explanation = intent.getStringExtra("gemini_explanation") ?: ""

        setContent {
            SafeLinkTheme {
                BlockedScreen(
                    url = url,
                    verdict = verdict,
                    explanation = explanation,
                    onGoBack = { finish() },
                    onOpenAnyway = {
                        BrowserUtils.openInSavedBrowser(this, url)
                        finish()
                    }
                )
            }
        }
    }
}

@Composable
fun BlockedScreen(
    url: String,
    verdict: String,
    explanation: String,
    onGoBack: () -> Unit,
    onOpenAnyway: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Background.copy(alpha = 0.95f)),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .wrapContentHeight(),
            shape = RoundedCornerShape(48.dp),
            color = SurfaceContainerLow,
            border = CardDefaults.outlinedCardBorder(true).copy(width = 0.5.dp, brush = Brush.verticalGradient(listOf(Color.White.copy(0.1f), Color.Transparent)))
        ) {
            Column(
                modifier = Modifier.padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(32.dp)
            ) {
                // Warning Icon with Halo
                Box(contentAlignment = Alignment.Center) {
                    Box(
                        modifier = Modifier
                            .size(128.dp)
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(ErrorContainer.copy(alpha = 0.4f), Color.Transparent)
                                ),
                                CircleShape
                            )
                    )
                    
                    val infiniteTransition = rememberInfiniteTransition(label = "rotate")
                    val rotation by infiniteTransition.animateFloat(
                        initialValue = 0f,
                        targetValue = 360f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(10000, easing = LinearEasing),
                            repeatMode = RepeatMode.Restart
                        ),
                        label = "rotation"
                    )

                    Box(
                        modifier = Modifier
                            .size(128.dp)
                            .rotate(rotation)
                            .border(4.dp, Error.copy(alpha = 0.2f), CircleShape)
                    )
                    
                    Surface(
                        modifier = Modifier.size(96.dp),
                        shape = CircleShape,
                        color = ErrorContainer
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = OnErrorContainer, modifier = Modifier.size(56.dp))
                        }
                    }
                }

                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "Danger\nDo not Open",
                        style = MaterialTheme.typography.headlineLarge,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        lineHeight = 40.sp
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "SafeLink blocked a high-threat URL to protect your identity.",
                        color = OnSurfaceVariant,
                        textAlign = TextAlign.Center,
                        fontWeight = FontWeight.Medium
                    )
                }

                // URL Card
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    color = SurfaceContainerHigh
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text(
                            text = "FLAGGED URL DETECTED",
                            style = MaterialTheme.typography.labelSmall,
                            color = OnSurfaceVariant,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 2.sp
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = url,
                            color = Error,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            fontSize = 14.sp,
                            modifier = Modifier
                                .background(Background, RoundedCornerShape(16.dp))
                                .padding(16.dp)
                                .fillMaxWidth()
                        )
                    }
                }

                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedButton(
                            onClick = onOpenAnyway,
                            modifier = Modifier
                                .weight(1f)
                                .height(56.dp),
                            shape = RoundedCornerShape(20.dp),
                            border = ButtonDefaults.outlinedButtonBorder.copy(width = 2.dp, brush = SolidColor(Error)),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Error)
                        ) {
                            Text("Open Anyway", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = onGoBack,
                            modifier = Modifier
                                .weight(1f)
                                .height(56.dp),
                            shape = RoundedCornerShape(20.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Primary, contentColor = Background)
                        ) {
                            Text("Go Back", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    TextButton(onClick = { /* Report */ }) {
                        Text(
                            text = "Report as false positive",
                            color = OnSurfaceVariant,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
    }
}

// Helper to provide SolidColor for BorderStroke
@Composable
fun SolidColor(color: Color) = androidx.compose.ui.graphics.SolidColor(color)
