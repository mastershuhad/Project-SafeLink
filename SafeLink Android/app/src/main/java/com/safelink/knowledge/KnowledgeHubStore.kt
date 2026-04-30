package com.safelink.knowledge

import android.content.Context
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File

/**
 * In-memory Knowledge Hub store.
 *
 * Loading priority:
 *   1. Internal storage (kh_*.json — updated by KnowledgeHubUpdater)
 *   2. Bundled assets (fallback, always available)
 */
class KnowledgeHubStore(private val context: Context) {

    private val gson = Gson()

    var brands: List<BrandEntry> = emptyList()
        private set
    var patterns: List<AttackPattern> = emptyList()
        private set
    var enrichments: Map<String, XAIEnrichment> = emptyMap()
        private set
    var version: KnowledgeHubVersion? = null
        private set

    fun load() {
        brands = loadJson("brands_lk.json", "kh_brands_lk.json",
            object : TypeToken<List<BrandEntry>>() {}) +
            loadJson("brands_global.json", "kh_brands_global.json",
                object : TypeToken<List<BrandEntry>>() {})

        patterns = loadJson("attack_patterns.json", "kh_attack_patterns.json",
            object : TypeToken<List<AttackPattern>>() {})

        val enrichList = loadJson<List<XAIEnrichment>>("xai_enrichments.json",
            "kh_xai_enrichments.json",
            object : TypeToken<List<XAIEnrichment>>() {})
        enrichments = enrichList.associateBy { it.brandId }
    }

    /** Returns the first brand whose domains or keywords match the URL. */
    fun findBrand(url: String): BrandEntry? {
        val urlLower = url.lowercase()
        return brands.firstOrNull { brand ->
            // Check if URL contains any keyword but is NOT on a legitimate domain
            brand.keywords.any { kw -> kw in urlLower }
        }
    }

    /** Returns the first attack pattern whose regex matches the URL. */
    fun findPattern(url: String): AttackPattern? {
        return patterns.firstOrNull { pattern ->
            try {
                Regex(pattern.pattern, RegexOption.IGNORE_CASE).containsMatchIn(url)
            } catch (e: Exception) {
                false
            }
        }
    }

    fun getEnrichment(brandId: String): XAIEnrichment? = enrichments[brandId]

    /** Levenshtein-based minimum edit distance to all brand display names. */
    fun minBrandDistance(name: String): Int {
        return brands.minOfOrNull { brand ->
            levenshtein(name.lowercase(), brand.displayName.lowercase())
        } ?: Int.MAX_VALUE
    }

    private inline fun <reified T> loadJson(
        assetFile: String,
        internalFile: String,
        typeToken: TypeToken<T>,
    ): T {
        // Try internal storage first (updated version)
        val internalPath = File(context.filesDir, internalFile)
        val json = if (internalPath.exists()) {
            internalPath.readText()
        } else {
            // Fallback to bundled assets
            try {
                context.assets.open(assetFile).bufferedReader().readText()
            } catch (e: Exception) {
                return emptyListFallback()
            }
        }
        return try {
            gson.fromJson(json, typeToken.type)
        } catch (e: Exception) {
            emptyListFallback()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> emptyListFallback(): T = emptyList<Any>() as T

    private fun levenshtein(a: String, b: String): Int {
        val dp = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) dp[i][0] = i
        for (j in 0..b.length) dp[0][j] = j
        for (i in 1..a.length) {
            for (j in 1..b.length) {
                dp[i][j] = if (a[i - 1] == b[j - 1]) dp[i - 1][j - 1]
                else minOf(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]) + 1
            }
        }
        return dp[a.length][b.length]
    }
}
