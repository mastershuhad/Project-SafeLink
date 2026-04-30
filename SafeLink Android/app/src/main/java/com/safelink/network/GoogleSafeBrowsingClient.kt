package com.safelink.network

import com.safelink.BuildConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Google Safe Browsing v4 client.
 * Called ONLY when ML verdict = SAFE — not for MALICIOUS or WARNING.
 * This avoids burning API quota on confirmed threats (~18% of URLs hit GSB).
 *
 * Returns true if URL is flagged by GSB, false if clean, null on any failure.
 */
class GoogleSafeBrowsingClient {

    private val apiKey = BuildConfig.GSB_API_KEY
    private val endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey"

    private val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    // LRU cache — 1000 entries
    private val cache = object : LinkedHashMap<String, Boolean>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Boolean>) = size > 1000
    }

    private val JSON = "application/json; charset=utf-8".toMediaType()

    /** Returns true if flagged, false if clean, null on error/no API key. */
    fun isMalicious(url: String): Boolean? {
        if (apiKey.isBlank()) return null

        cache[url]?.let { return it }

        return try {
            val body = buildRequestBody(url)
            val request = Request.Builder()
                .url(endpoint)
                .post(body.toRequestBody(JSON))
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null

                val responseBody = response.body?.string() ?: return null
                val json = JSONObject(responseBody)
                val hasMatches = json.has("matches") && json.getJSONArray("matches").length() > 0

                cache[url] = hasMatches
                hasMatches
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun buildRequestBody(url: String): String {
        return JSONObject().apply {
            put("client", JSONObject().apply {
                put("clientId", "safelink-android")
                put("clientVersion", "1.0.0")
            })
            put("threatInfo", JSONObject().apply {
                put("threatTypes", JSONArray().apply {
                    put("MALWARE")
                    put("SOCIAL_ENGINEERING")
                    put("UNWANTED_SOFTWARE")
                    put("POTENTIALLY_HARMFUL_APPLICATION")
                })
                put("platformTypes", JSONArray().apply { put("ANDROID") })
                put("threatEntryTypes", JSONArray().apply { put("URL") })
                put("threatEntries", JSONArray().apply {
                    put(JSONObject().apply { put("url", url) })
                })
            })
        }.toString()
    }
}
