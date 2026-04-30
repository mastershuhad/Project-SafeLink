package com.safelink.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

object BrowserUtils {

    data class BrowserInfo(val packageName: String, val label: String)

    fun getInstalledBrowsers(context: Context): List<BrowserInfo> {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.example.com"))
        intent.addCategory(Intent.CATEGORY_BROWSABLE)
        val pm = context.packageManager
        return pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
            .filter { it.activityInfo.packageName != context.packageName }
            .map { BrowserInfo(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
            .distinctBy { it.packageName }
            .sortedBy { it.label }
    }

    fun getSavedBrowserPackage(context: Context): String? =
        context.getSharedPreferences("safelink_prefs", Context.MODE_PRIVATE)
            .getString("selected_browser_pkg", null)

    fun saveBrowserPackage(context: Context, packageName: String) {
        context.getSharedPreferences("safelink_prefs", Context.MODE_PRIVATE)
            .edit().putString("selected_browser_pkg", packageName).apply()
    }

    fun getSavedBrowserLabel(context: Context): String? {
        val pkg = getSavedBrowserPackage(context) ?: return null
        return try {
            context.packageManager.getApplicationLabel(
                context.packageManager.getApplicationInfo(pkg, 0)
            ).toString()
        } catch (_: Exception) { null }
    }

    fun openInSavedBrowser(context: Context, url: String) {
        val pkg = getSavedBrowserPackage(context)
        if (pkg != null) {
            try {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                    setPackage(pkg)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
                return
            } catch (_: Exception) { /* browser uninstalled — fall through */ }
        }
        // No browser selected or failed: show chooser (bypasses SafeLink as default)
        context.startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_VIEW, Uri.parse(url)), "Open with"
            ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        )
    }

    fun isDefaultBrowser(context: Context): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.example.com"))
        intent.addCategory(Intent.CATEGORY_BROWSABLE)
        val resolved = context.packageManager.resolveActivity(
            intent, PackageManager.MATCH_DEFAULT_ONLY
        )
        return resolved?.activityInfo?.packageName == context.packageName
    }
}
