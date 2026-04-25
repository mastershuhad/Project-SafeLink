package com.safelink.knowledge

import android.content.Context
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Downloads updated Knowledge Hub JSON files from GitHub once per day.
 * Saves as kh_{filename} in internal storage.
 * Reloads KnowledgeHubStore after successful update.
 */
class KnowledgeHubUpdater(
    private val context: Context,
    private val store: KnowledgeHubStore,
) {
    companion object {
        private const val PREFS_KEY = "kh_last_update"
        private const val UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000L  // 24 hours

        // GitHub raw content base URL — update with your actual repo
        private const val BASE_URL =
            "https://raw.githubusercontent.com/YOUR_USERNAME/safelink-knowledge-hub/main"

        private val FILES = listOf(
            "version.json",
            "brands_lk.json",
            "brands_global.json",
            "attack_patterns.json",
            "xai_enrichments.json",
        )
    }

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val prefs = context.getSharedPreferences("safelink_kh", Context.MODE_PRIVATE)

    fun checkAndUpdate() {
        if (BASE_URL.contains("YOUR_USERNAME")) return  // repo not configured — use bundled assets
        val lastUpdate = prefs.getLong(PREFS_KEY, 0L)
        if (System.currentTimeMillis() - lastUpdate < UPDATE_INTERVAL_MS) return

        try {
            // Fetch version.json first to check if update is needed
            val remoteVersion = fetchFile("version.json") ?: return
            val localVersionFile = File(context.filesDir, "kh_version.json")
            if (localVersionFile.exists() && localVersionFile.readText() == remoteVersion) {
                // Already up to date
                prefs.edit().putLong(PREFS_KEY, System.currentTimeMillis()).apply()
                return
            }

            // Download all files
            var allSuccess = true
            for (filename in FILES) {
                val content = fetchFile(filename)
                if (content != null) {
                    File(context.filesDir, "kh_$filename").writeText(content)
                } else {
                    allSuccess = false
                    android.util.Log.w("KnowledgeHubUpdater", "Failed to fetch $filename")
                }
            }

            if (allSuccess) {
                store.load()
                prefs.edit().putLong(PREFS_KEY, System.currentTimeMillis()).apply()
                android.util.Log.i("KnowledgeHubUpdater", "Knowledge Hub updated successfully")
            }
        } catch (e: Exception) {
            android.util.Log.w("KnowledgeHubUpdater", "Update failed: ${e.message}")
        }
    }

    private fun fetchFile(filename: String): String? {
        return try {
            val request = Request.Builder()
                .url("$BASE_URL/$filename")
                .build()
            val response = client.newCall(request).execute()
            if (response.isSuccessful) response.body?.string() else null
        } catch (e: Exception) {
            null
        }
    }
}
