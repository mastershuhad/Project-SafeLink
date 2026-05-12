package com.safelink.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.safelink.App
import com.safelink.data.SafeLinkDatabase
import com.safelink.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

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
                .height(64.dp)
                .padding(horizontal = 24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Shield, contentDescription = null, tint = Primary, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "SafeLink",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = OnSurface
            )
        }

        // Hero Section
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(
                modifier = Modifier.size(64.dp),
                shape = RoundedCornerShape(24.dp),
                color = SurfaceContainerLow,
                tonalElevation = 4.dp,
                border = CardDefaults.outlinedCardBorder(true).copy(width = 0.5.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(36.dp), tint = Primary.copy(alpha = 0.2f))
                    Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(24.dp), tint = Primary)
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = "SafeLink", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                text = "Protecting you from harmful links",
                style = MaterialTheme.typography.labelSmall,
                color = OnSurfaceVariant,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.sp
            )
        }

        // Protection Section
        SettingsSection(title = "Protection") {
            val prefs = remember { context.getSharedPreferences("safelink_prefs", android.content.Context.MODE_PRIVATE) }
            var scanOn by remember { mutableStateOf(App.protectionEnabled) }
            var popupOn by remember { mutableStateOf(prefs.getBoolean("show_popup", true)) }
            var aiOn by remember { mutableStateOf(prefs.getBoolean("show_ai", true)) }

            ToggleItem(
                label = "Background URL Scanning",
                desc = "Check links while you browse apps",
                value = scanOn,
                onToggle = { 
                    scanOn = it
                    App.protectionEnabled = it
                    prefs.edit().putBoolean("protection_enabled", it).apply()
                }
            )
            ToggleItem(
                label = "Show popup for WARNING links",
                desc = "Instant alerts for suspicious activity",
                value = popupOn,
                onToggle = { 
                    popupOn = it
                    prefs.edit().putBoolean("show_popup", it).apply()
                }
            )
            ToggleItem(
                label = "AI explanations (Gemini)",
                desc = "Simple reasons why a link is blocked",
                value = aiOn,
                onToggle = { 
                    aiOn = it
                    prefs.edit().putBoolean("show_ai", it).apply()
                }
            )
        }

        // Privacy Section
        SettingsSection(title = "Privacy") {
            ActionItem(
                icon = Icons.Default.Delete,
                label = "Clear Scan History",
                color = Error,
                onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            SafeLinkDatabase.getInstance(context).scanDao().clearAll()
                        }
                    }
                }
            )
            ActionItem(icon = Icons.Default.Flag, label = "Report False Positive", color = Tertiary)
        }

        // About Section
        SettingsSection(title = "About") {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = SurfaceContainer
            ) {
                Row(
                    modifier = Modifier.padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = SurfaceContainerHigh,
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(Icons.Default.Info, contentDescription = null, tint = Primary)
                            }
                        }
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(text = "SafeLink v1.0", fontWeight = FontWeight.Bold)
                    }
                    Text(
                        text = "Up to date",
                        style = MaterialTheme.typography.labelSmall,
                        color = OnSurfaceVariant.copy(alpha = 0.5f),
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                }
            }
            ActionItem(icon = Icons.Default.Help, label = "How SafeLink works", color = Primary)
        }
        
        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier = Modifier.padding(24.dp)) {
        Text(
            text = title.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            color = Primary,
            fontWeight = FontWeight.Black,
            letterSpacing = 2.sp,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp)
        )
        Surface(
            shape = RoundedCornerShape(32.dp),
            color = SurfaceContainerLow,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(8.dp), content = content)
        }
    }
}

@Composable
fun ToggleItem(label: String, desc: String, value: Boolean, onToggle: (Boolean) -> Unit) {
    Surface(
        onClick = { onToggle(!value) },
        shape = RoundedCornerShape(24.dp),
        color = if (value) SurfaceContainerHigh else SurfaceContainer,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = label, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(text = desc, style = MaterialTheme.typography.bodySmall, color = OnSurfaceVariant)
            }
            Switch(
                checked = value,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Background,
                    checkedTrackColor = PrimaryContainer,
                    uncheckedThumbColor = OnSurfaceVariant,
                    uncheckedTrackColor = SurfaceVariant
                )
            )
        }
    }
}

@Composable
fun ActionItem(icon: ImageVector, label: String, color: Color, onClick: () -> Unit = {}) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(24.dp),
        color = SurfaceContainer,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = SurfaceContainerHigh,
                    modifier = Modifier.size(40.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
                    }
                }
                Spacer(modifier = Modifier.width(16.dp))
                Text(text = label, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = OnSurfaceVariant, modifier = Modifier.size(18.dp))
        }
    }
}
