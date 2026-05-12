package com.safelink.ui

import android.app.role.RoleManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.safelink.ui.history.HistoryScreen
import com.safelink.ui.history.ScanDetailScreen
import com.safelink.ui.home.HomeScreen
import com.safelink.ui.settings.SettingsScreen
import com.safelink.ui.theme.SafeLinkTheme
import com.safelink.ui.theme.SurfaceContainerLow
import kotlinx.coroutines.delay

sealed class Screen(val route: String, val label: String, val icon: ImageVector) {
    object Initialization : Screen("initialization", "Init", Icons.Default.Shield)
    object Onboarding : Screen("onboarding", "Onboarding", Icons.Default.Shield)
    object BrowserSelection : Screen("browser_selection", "Browser", Icons.Default.Shield)
    object Home : Screen("home", "Home", Icons.Default.Home)
    object History : Screen("history", "History", Icons.Default.History)
    object Settings : Screen("settings", "Settings", Icons.Default.Settings)
    object ScanDetail : Screen("scan_detail/{scanId}", "Detail", Icons.Default.Shield) {
        fun createRoute(scanId: Long) = "scan_detail/$scanId"
    }
}

class MainComposeActivity : ComponentActivity() {

    private companion object {
        const val RC_BROWSER_ROLE = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            SafeLinkTheme {
                val navController = rememberNavController()
                val items = listOf(Screen.Home, Screen.History, Screen.Settings)
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination
                
                // Show bottom bar only on main screens
                val showBottomBar = currentDestination?.route in listOf(Screen.Home.route, Screen.History.route, Screen.Settings.route)

                Scaffold(
                    bottomBar = {
                        if (showBottomBar) {
                            NavigationBar(
                                containerColor = SurfaceContainerLow.copy(alpha = 0.9f),
                                tonalElevation = 0.dp,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                            ) {
                                items.forEach { screen ->
                                    NavigationBarItem(
                                        icon = { Icon(screen.icon, contentDescription = null) },
                                        label = { Text(screen.label) },
                                        selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                                        onClick = {
                                            navController.navigate(screen.route) {
                                                popUpTo(navController.graph.findStartDestination().id) {
                                                    saveState = true
                                                }
                                                launchSingleTop = true
                                                restoreState = true
                                            }
                                        }
                                    )
                                }
                            }
                        }
                    }
                ) { innerPadding ->
                    NavHost(
                        navController,
                        startDestination = Screen.Initialization.route,
                        Modifier.padding(if (showBottomBar) innerPadding else PaddingValues(0.dp))
                    ) {
                        composable(Screen.Initialization.route) {
                            InitializationScreen { modelsReady ->
                                if (isSetupComplete()) {
                                    navController.navigate(Screen.Home.route) {
                                        popUpTo(Screen.Initialization.route) { inclusive = true }
                                    }
                                } else {
                                    navController.navigate(Screen.Onboarding.route) {
                                        popUpTo(Screen.Initialization.route) { inclusive = true }
                                    }
                                }
                            }
                        }
                        
                        composable(Screen.Onboarding.route) {
                            OnboardingScreen {
                                requestDefaultBrowser()
                                // We'll check if it became default in onResume or by monitoring state
                            }
                        }
                        
                        composable(Screen.BrowserSelection.route) {
                            BrowserSelectionScreen(
                                onBack = { navController.popBackStack() },
                                onBrowserSelected = { pkg ->
                                    BrowserUtils.saveBrowserPackage(this@MainComposeActivity, pkg)
                                    navController.navigate(Screen.Home.route) {
                                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                                    }
                                }
                            )
                        }

                        composable(Screen.Home.route) { HomeScreen() }
                        composable(Screen.History.route) { 
                            HistoryScreen(
                                onBack = { navController.popBackStack() },
                                onDetailClick = { scanId ->
                                    navController.navigate(Screen.ScanDetail.createRoute(scanId))
                                }
                            ) 
                        }
                        composable(Screen.Settings.route) { SettingsScreen() }
                        
                        composable(
                            route = Screen.ScanDetail.route,
                            arguments = listOf(navArgument("scanId") { type = NavType.LongType })
                        ) { backStackEntry ->
                            val scanId = backStackEntry.arguments?.getLong("scanId") ?: -1L
                            ScanDetailScreen(scanId = scanId, onBack = { navController.popBackStack() })
                        }
                    }
                }
                
                // Monitor for default browser changes to advance from onboarding
                LaunchedEffect(currentDestination?.route) {
                    if (currentDestination?.route == Screen.Onboarding.route) {
                        while (currentDestination?.route == Screen.Onboarding.route) {
                            if (BrowserUtils.isDefaultBrowser(this@MainComposeActivity)) {
                                navController.navigate(Screen.BrowserSelection.route)
                                break
                            }
                            delay(1000)
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // If we are in Onboarding and user just came back from settings, check if they set it
        // This is a fallback to the LaunchedEffect loop
    }

    private fun requestDefaultBrowser() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val rm = getSystemService(RoleManager::class.java)
            if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
                @Suppress("DEPRECATION")
                startActivityForResult(
                    rm.createRequestRoleIntent(RoleManager.ROLE_BROWSER),
                    RC_BROWSER_ROLE
                )
                return
            }
        }
        startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
    }

    private fun isSetupComplete(): Boolean =
        BrowserUtils.isDefaultBrowser(this) && BrowserUtils.getSavedBrowserPackage(this) != null
}
