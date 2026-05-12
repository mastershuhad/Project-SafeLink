package com.safelink.ui

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.safelink.App
import com.safelink.ui.theme.*
import kotlinx.coroutines.delay

@Composable
fun InitializationScreen(onInitializationComplete: (Boolean) -> Unit) {
    var initializationText by remember { mutableStateOf("Initializing safety models...") }
    
    LaunchedEffect(Unit) {
        // Wait for models to be ready (timeout after 15s)
        var waited = 0
        while (!App.modelsReady && !App.modelsFailed && waited < 15_000) {
            delay(500)
            waited += 500
        }
        
        if (App.modelsFailed || !App.modelsReady) {
            initializationText = if (App.modelsFailed) "Critical error during initialization." 
                                else "Initialization taking longer than expected..."
            delay(2000)
        } else {
            initializationText = "Securing your device..."
            delay(1000)
        }
        
        onInitializationComplete(App.modelsReady)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Background),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(contentAlignment = Alignment.Center) {
            // Halo Background
            Box(
                modifier = Modifier
                    .size(200.dp)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(PrimaryContainer.copy(alpha = 0.2f), Color.Transparent)
                        ),
                        CircleShape
                    )
            )

            // Animated Shield
            val infiniteTransition = rememberInfiniteTransition(label = "loader")
            val scale by infiniteTransition.animateFloat(
                initialValue = 0.8f,
                targetValue = 1.1f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1500, easing = EaseInOut),
                    repeatMode = RepeatMode.Reverse
                ),
                label = "scale"
            )

            Surface(
                modifier = Modifier
                    .size(120.dp)
                    .clip(CircleShape),
                color = SurfaceContainer,
                tonalElevation = 4.dp
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Default.Shield,
                        contentDescription = null,
                        modifier = Modifier.size(60.dp),
                        tint = Primary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(48.dp))
        
        Text(
            text = "SafeLink",
            style = MaterialTheme.typography.headlineMedium,
            color = OnSurface,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = initializationText,
            color = OnSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        CircularProgressIndicator(
            modifier = Modifier.size(24.dp),
            color = Primary,
            strokeWidth = 2.dp
        )
    }
}
