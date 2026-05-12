package com.safelink.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.safelink.ui.components.SignatureGradient
import com.safelink.ui.theme.*

@Composable
fun BrowserSelectionScreen(onBack: () -> Unit, onBrowserSelected: (String) -> Unit) {
    val context = LocalContext.current
    val browsers = remember { BrowserUtils.getInstalledBrowsers(context) }
    var selectedPackage by remember { mutableStateOf<String?>(BrowserUtils.getSavedBrowserPackage(context)) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Background)
    ) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onBack,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(SurfaceContainerHigh)
            ) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back")
            }
            Spacer(modifier = Modifier.width(16.dp))
            Text(
                text = "SAFELINK SETUP",
                style = MaterialTheme.typography.labelMedium,
                color = OnSurfaceVariant,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .weight(1f)
        ) {
            Text(
                text = "Select Real Browser",
                style = MaterialTheme.typography.headlineMedium,
                color = Primary,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Choose where SafeLink opens your secure links.",
                style = MaterialTheme.typography.bodyMedium,
                color = OnSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(modifier = Modifier.height(32.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                items(browsers) { browser ->
                    BrowserItem(
                        info = browser,
                        isSelected = selectedPackage == browser.packageName,
                        onSelect = { selectedPackage = it }
                    )
                }
            }
        }

        // Footer
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp)
        ) {
            // Info Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = SurfaceContainerHigh,
                border = CardDefaults.outlinedCardBorder(true).copy(width = 0.5.dp)
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(PrimaryContainer.copy(alpha = 0.2f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Shield, contentDescription = null, tint = Primary, modifier = Modifier.size(20.dp))
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                    Column {
                        Text(
                            text = "Always Protected",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = OnSurface
                        )
                        Text(
                            text = "Scanning URLs for malware instantly.",
                            style = MaterialTheme.typography.bodySmall,
                            color = OnSurfaceVariant
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = { selectedPackage?.let { onBrowserSelected(it) } },
                enabled = selectedPackage != null,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent,
                    disabledContainerColor = SurfaceContainerHigh.copy(alpha = 0.5f)
                ),
                contentPadding = PaddingValues()
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(if (selectedPackage != null) SignatureGradient else SolidColor(Color.Transparent)),
                    contentAlignment = Alignment.Center
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Continue",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = if (selectedPackage != null) OnPrimaryContainer else OnSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Icon(
                            Icons.Default.ArrowForward,
                            contentDescription = null,
                            tint = if (selectedPackage != null) OnPrimaryContainer else OnSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun BrowserItem(
    info: BrowserUtils.BrowserInfo,
    isSelected: Boolean,
    onSelect: (String) -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect(info.packageName) },
        shape = RoundedCornerShape(20.dp),
        color = if (isSelected) SurfaceContainer else SurfaceContainerLow,
        border = if (isSelected) 
            CardDefaults.outlinedCardBorder(true).copy(width = 1.5.dp, brush = SignatureGradient)
        else 
            CardDefaults.outlinedCardBorder(true).copy(width = 0.5.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(SurfaceContainerHigh, RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center
            ) {
                // In a real app we'd load the icon, using Shield as placeholder
                Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(24.dp), tint = OnSurfaceVariant)
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = info.label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = OnSurface
                )
                Text(
                    text = if (info.packageName.contains("chrome")) "RECOMMENDED" else "BROWSER",
                    style = MaterialTheme.typography.labelSmall,
                    color = OnSurfaceVariant,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp
                )
            }
            RadioButton(
                selected = isSelected,
                onClick = { onSelect(info.packageName) },
                colors = RadioButtonDefaults.colors(selectedColor = Primary)
            )
        }
    }
}
