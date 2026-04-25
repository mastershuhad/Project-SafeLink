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
 * Gemini 2.0 Flash client — called ONLY on WARNING verdict.
 * RAG-enhanced: includes Knowledge Hub context in the prompt.
 *
 * On any failure, returns "" — XAI engine reason is always shown as fallback.
 * maxOutputTokens=60, temperature=0.3 for concise, factual responses.
 */
class GeminiClient {

    private val apiKey = BuildConfig.GEMINI_API_KEY
    private val endpoint =
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$apiKey"

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val JSON = "application/json; charset=utf-8".toMediaType()

    /**
     * Generates a plain-English WARNING explanation for elderly users.
     * [khContext] is the Knowledge Hub context injected into the prompt.
     * Returns empty string on failure.
     */
    fun explainWarning(url: String, xaiReason: String, khContext: String): String {
        if (apiKey.isBlank()) return ""

        return try {
            val prompt = buildPrompt(url, xaiReason, khContext)
            val body = buildRequestBody(prompt)
            val request = Request.Builder()
                .url(endpoint)
                .post(body.toRequestBody(JSON))
                .build()

            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return ""

            val responseBody = response.body?.string() ?: return ""
            val json = JSONObject(responseBody)
            val candidates = json.optJSONArray("candidates") ?: return ""
            if (candidates.length() == 0) return ""

            val content = candidates.getJSONObject(0)
                .optJSONObject("content") ?: return ""
            val parts = content.optJSONArray("parts") ?: return ""
            if (parts.length() == 0) return ""

            parts.getJSONObject(0).optString("text", "").trim()
        } catch (e: Exception) {
            ""
        }
    }

    private fun buildPrompt(url: String, xaiReason: String, khContext: String): String {
        return """
You are SafeLink, a security assistant helping elderly people in Sri Lanka stay safe online.

A suspicious link has been detected: $url

Security analysis: $xaiReason

${if (khContext.isNotBlank()) "Additional context: $khContext\n" else ""}
In 1-2 simple sentences (no jargon), explain why this link is suspicious and what the person should do.
Write as if talking to your grandmother. Do not use technical terms.
        """.trimIndent()
    }

    private fun buildRequestBody(prompt: String): String {
        return JSONObject().apply {
            put("contents", JSONArray().apply {
                put(JSONObject().apply {
                    put("parts", JSONArray().apply {
                        put(JSONObject().apply { put("text", prompt) })
                    })
                })
            })
            put("generationConfig", JSONObject().apply {
                put("maxOutputTokens", 60)
                put("temperature", 0.3)
            })
        }.toString()
    }
}
