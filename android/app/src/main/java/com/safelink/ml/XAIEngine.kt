package com.safelink.ml

import com.safelink.knowledge.KnowledgeHubStore

data class XAIResult(
    val primaryReason: String,
    val allReasons: List<String>,
    val geminiContext: String,
    val matchedBrand: String?,
)

/**
 * Rule-based on-device XAI engine — <5ms, no network.
 *
 * Priority:
 *   1. Brand impersonation (Knowledge Hub brand match)
 *   2. Attack pattern match (Knowledge Hub patterns)
 *   3. Feature rule map (top-3 by weight × value)
 */
object XAIEngine {

    // (featureIndex, weight, threshold, elderlyFriendlyReason)
    private val REASON_MAP: List<Triple<Int, Float, String>> = listOf(
        Triple(8,  5.0f, "This link contains an '@' sign — a trick used to hide the real website address"),
        Triple(20, 4.5f, "This link has a suspicious web address ending (like .xyz or .tk) that is commonly used for scams"),
        Triple(22, 4.0f, "This link contains suspicious words like 'login', 'verify', or 'secure' — banks never ask for passwords via links"),
        Triple(23, 3.8f, "This link pretends to be a well-known brand or bank to trick you"),
        Triple(19, 3.5f, "This link goes directly to an IP address instead of a real website name — this is very unusual and suspicious"),
        Triple(24, 3.2f, "This is a shortened link that hides the real destination"),
        Triple(0,  2.8f, "This link is unusually long — scammers use long links to confuse people"),
        Triple(4,  2.5f, "This link has too many dots, which is a common trick used in phishing"),
        Triple(5,  2.3f, "This link has many hyphens, which scammers use to make fake sites look real"),
        Triple(34, 2.0f, "This link has a real website address hidden inside a longer fake one"),
        Triple(17, 1.8f, "This link does not use a secure connection (no padlock) — your information could be stolen"),
        Triple(33, 1.5f, "This link contains lots of numbers in the website address, which is unusual for real websites"),
        Triple(32, 1.3f, "This link uses special encoded characters to hide its true destination"),
        Triple(26, 1.2f, "This link uses an unusual port number, which is not normal for real websites"),
        Triple(27, 1.0f, "This link has an unusual double-slash in the path, which may indicate a redirect trick"),
    )

    fun explain(
        rawFeatures: FloatArray,
        knowledgeHub: KnowledgeHubStore,
        url: String,
        verdict: Verdict,
    ): XAIResult {
        // --- 1. Check brand impersonation ---
        val brandMatch = knowledgeHub.findBrand(url)
        if (brandMatch != null) {
            val enrichment = knowledgeHub.getEnrichment(brandMatch.id)
            val reason = enrichment?.xaiReason
                ?: "This link is pretending to be ${brandMatch.displayName} to steal your information"
            val gemCtx = "Brand: ${brandMatch.displayName}. Legitimate domain: ${brandMatch.domains.firstOrNull() ?: "unknown"}."
            return XAIResult(
                primaryReason = reason,
                allReasons = listOf(reason),
                geminiContext = gemCtx,
                matchedBrand = brandMatch.displayName,
            )
        }

        // --- 2. Check attack patterns ---
        val patternMatch = knowledgeHub.findPattern(url)
        if (patternMatch != null) {
            val gemCtx = "Attack pattern: ${patternMatch.pattern}. Type: ${patternMatch.type}."
            return XAIResult(
                primaryReason = patternMatch.elderlyWarning,
                allReasons = listOf(patternMatch.elderlyWarning),
                geminiContext = gemCtx,
                matchedBrand = null,
            )
        }

        // --- 3. Feature rule map — rank by weight × feature_value ---
        val scored = REASON_MAP.mapNotNull { (featIdx, weight, reason) ->
            if (featIdx < rawFeatures.size) {
                val score = weight * rawFeatures[featIdx]
                if (score > 0f) Triple(score, featIdx, reason)
                else null
            } else null
        }.sortedByDescending { it.first }

        val topReasons = scored.take(3).map { it.third }

        val primary = if (topReasons.isNotEmpty()) {
            topReasons.first()
        } else {
            when (verdict) {
                Verdict.MALICIOUS -> "This link shows multiple signs of a phishing or malware attack"
                Verdict.WARNING   -> "This link has some suspicious features that need caution"
                else              -> "This link appears to be safe"
            }
        }

        val gemCtx = "Top features: ${scored.take(3).joinToString(", ") { "f${it.second}=${rawFeatures[it.second]}" }}"

        return XAIResult(
            primaryReason = primary,
            allReasons = topReasons.ifEmpty { listOf(primary) },
            geminiContext = gemCtx,
            matchedBrand = null,
        )
    }
}

