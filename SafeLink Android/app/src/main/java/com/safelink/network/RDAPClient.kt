package com.safelink.network

import android.net.Uri
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit

/**
 * RDAP domain age lookup.
 * Queries rdap.org/domain/{domain}, parses "registration" event date.
 * Returns domain age in days, or -1f on any failure.
 *
 * Must run parallel with ML inference — withTimeoutOrNull(150ms) enforced by caller.
 */
class RDAPClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(2, TimeUnit.SECONDS)
        .readTimeout(3, TimeUnit.SECONDS)
        .build()

    // LRU cache — 500 entries
    private val cache = object : LinkedHashMap<String, Float>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Float>) = size > 500
    }

    private val rdapDateFormats = listOf(
        DateTimeFormatter.ISO_DATE_TIME,
        DateTimeFormatter.ISO_OFFSET_DATE_TIME,
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ"),
        DateTimeFormatter.ofPattern("yyyy-MM-dd"),
    )

    fun getDomainAgeDays(url: String): Float {
        val domain = extractDomain(url) ?: return -1f

        cache[domain]?.let { return it }

        return try {
            val request = Request.Builder()
                .url("https://rdap.org/domain/$domain")
                .header("Accept", "application/json")
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return cacheAndReturn(domain, -1f)

                val body = response.body?.string() ?: return cacheAndReturn(domain, -1f)
                val json = JSONObject(body)
                val events = json.optJSONArray("events") ?: return cacheAndReturn(domain, -1f)

                var registrationDate: LocalDate? = null
                for (i in 0 until events.length()) {
                    val event = events.getJSONObject(i)
                    if (event.optString("eventAction") == "registration") {
                        val dateStr = event.optString("eventDate") ?: continue
                        registrationDate = parseDate(dateStr)
                        break
                    }
                }

                val ageDays = registrationDate?.let {
                    ChronoUnit.DAYS.between(it, LocalDate.now()).toFloat()
                } ?: -1f

                cacheAndReturn(domain, ageDays)
            }
        } catch (e: Exception) {
            cacheAndReturn(domain, -1f)
        }
    }

    private fun extractDomain(url: String): String? {
        return try {
            val normalized = if ("://" !in url) "http://$url" else url
            val host = Uri.parse(normalized).host ?: return null
            host.removePrefix("www.").lowercase().ifBlank { null }
        } catch (e: Exception) {
            null
        }
    }

    private fun parseDate(dateStr: String): LocalDate? {
        for (fmt in rdapDateFormats) {
            try {
                return LocalDate.parse(dateStr.take(10), DateTimeFormatter.ISO_DATE)
            } catch (_: Exception) {}
        }
        return null
    }

    private fun cacheAndReturn(domain: String, value: Float): Float {
        cache[domain] = value
        return value
    }
}
