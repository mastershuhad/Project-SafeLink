package com.safelink.network

import android.content.Context

/**
 * Auto-trust: domains that score SAFE at ≥0.90 confidence for 5+ consecutive scans
 * are promoted to the dynamic whitelist. Persisted in SharedPreferences.
 * Static whitelist domains are never added (no need).
 */
class DynamicWhitelist(context: Context) {

    companion object {
        private const val PREFS_NAME = "safelink_dynamic_wl"
        private const val KEY_TRUSTED = "trusted_domains"
        private const val KEY_COUNTS = "scan_counts"
        private const val REQUIRED_SCANS = 5
        private const val MIN_CONFIDENCE = 0.90f
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // domain → scan count (JSON encoded in prefs)
    private val scanCounts: MutableMap<String, Int> by lazy { loadCounts() }
    private val trustedDomains: MutableSet<String> by lazy { loadTrusted() }

    fun isTrusted(domain: String): Boolean = trustedDomains.contains(domain)

    fun recordSafeScan(domain: String, confidence: Float) {
        if (confidence < MIN_CONFIDENCE) return
        if (trustedDomains.contains(domain)) return

        val count = (scanCounts[domain] ?: 0) + 1
        scanCounts[domain] = count

        if (count >= REQUIRED_SCANS) {
            trustedDomains.add(domain)
            android.util.Log.i("DynamicWhitelist", "Promoted to trusted: $domain")
        }

        persist()
    }

    private fun loadTrusted(): MutableSet<String> {
        val raw = prefs.getStringSet(KEY_TRUSTED, emptySet()) ?: emptySet()
        return raw.toMutableSet()
    }

    private fun loadCounts(): MutableMap<String, Int> {
        val raw = prefs.getString(KEY_COUNTS, "{}") ?: "{}"
        return try {
            val json = org.json.JSONObject(raw)
            val map = mutableMapOf<String, Int>()
            json.keys().forEach { key -> map[key] = json.getInt(key) }
            map
        } catch (e: Exception) {
            mutableMapOf()
        }
    }

    private fun persist() {
        val countsJson = org.json.JSONObject(scanCounts.mapValues { it.value }).toString()
        prefs.edit()
            .putStringSet(KEY_TRUSTED, trustedDomains)
            .putString(KEY_COUNTS, countsJson)
            .apply()
    }
}
