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
 *   3. Threshold-based feature rules (top-3 by weight)
 *
 * Feature indices mirror FeatureExtractor.kt (22-feature set, PRD v5.1):
 *   3=num_dots       4=num_hyphens      6=num_subdomains   7=is_https
 *   8=has_ip_host    9=has_at_in_url   10=has_homoglyphs  11=has_hex_encoding
 *  12=is_url_shortener  13=is_suspicious_tld  14=digit_ratio  15=special_char_ratio
 *  16=host_entropy  17=path_entropy   18=min_brand_distance  19=brand_in_subdomain
 *  20=url_depth     21=has_punycode
 */
object XAIEngine {

    /**
     * Rule fires when: invert=false → threshold < feature <= maxThreshold
     *                  invert=true  → feature <= threshold
     * maxThreshold defaults to MAX_VALUE (open-ended upper bound).
     * Score is the fixed weight — not multiplied by raw value.
     */
    private data class Rule(
        val featIdx: Int,
        val threshold: Float,
        val weight: Float,
        val reason: String,
        val invert: Boolean = false,
        val maxThreshold: Float = Float.MAX_VALUE,
    )

    private val RULES = listOf(
        Rule(9,  0f,  5.0f, "This link contains an '@' sign — a trick used to hide the real website address"),
        Rule(8,  0f,  4.5f, "This link goes directly to an IP address instead of a real website name — very unusual and suspicious"),
        Rule(13, 0f,  4.5f, "This link has a suspicious web address ending (like .xyz or .tk) that is commonly used for scams"),
        Rule(19, 0f,  4.5f, "This link pretends to be a well-known brand or bank to trick you"),
        Rule(18, 0f,  4.2f, "This link closely mimics a real brand name — it may be a typosquatting site",
             maxThreshold = 3f),   // fires when 0 < min_brand_distance <= 3
        Rule(10, 0f,  4.0f, "This link uses look-alike characters (homoglyphs) to impersonate a trusted website"),
        Rule(21, 0f,  3.8f, "This link uses international character encoding (Punycode) to disguise a fake domain"),
        Rule(12, 0f,  3.2f, "This is a shortened link that hides the real destination"),
        Rule(4,  2f,  2.5f, "This link has many hyphens — scammers use this pattern to make fake sites look real"),
        Rule(3,  4f,  2.3f, "This link has too many dots, which is a common trick used in phishing"),
        Rule(11, 0f,  1.8f, "This link uses special encoded characters to hide its true destination"),
        Rule(7,  0f,  1.8f, "This link does not use a secure connection (no padlock) — your information could be stolen", invert = true),
        Rule(16, 3.5f, 1.6f, "This website address has very high randomness — real websites use readable names"),
        Rule(14, 0.3f, 1.5f, "This link contains an unusually high proportion of numbers, which is unusual for real websites"),
        Rule(15, 0.1f, 1.3f, "This link contains unusual special characters that real websites don't normally use"),
        Rule(6,  2f,  1.0f, "This link has many sub-addresses, which can be used to disguise a fake website"),
    )

    fun explain(
        rawFeatures: FloatArray,
        knowledgeHub: KnowledgeHubStore,
        url: String,
        verdict: Verdict,
    ): XAIResult {
        // --- 1. Brand impersonation (Knowledge Hub) ---
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

        // --- 2. Attack pattern (Knowledge Hub) ---
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

        // --- 3. Threshold-based feature rules ---
        data class FiredRule(val rule: Rule, val value: Float)

        val fired = RULES.mapNotNull { rule ->
            if (rule.featIdx >= rawFeatures.size) return@mapNotNull null
            val value = rawFeatures[rule.featIdx]
            val triggered = if (rule.invert)
                value <= rule.threshold
            else
                value > rule.threshold && value <= rule.maxThreshold
            if (triggered) FiredRule(rule, value) else null
        }.sortedByDescending { it.rule.weight }

        val topReasons = fired.take(3).map { it.rule.reason }

        val primary = topReasons.firstOrNull() ?: when (verdict) {
            Verdict.MALICIOUS -> "This link shows multiple signs of a phishing or malware attack"
            Verdict.WARNING   -> "This link has some suspicious features — proceed with caution"
            else              -> "This link appears to be safe"
        }

        val gemCtx = "Top features: " + fired.take(3).joinToString(", ") {
            "f${it.rule.featIdx}=${it.value}"
        }

        return XAIResult(
            primaryReason = primary,
            allReasons = topReasons.ifEmpty { listOf(primary) },
            geminiContext = gemCtx,
            matchedBrand = null,
        )
    }
}
