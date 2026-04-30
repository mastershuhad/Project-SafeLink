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
 * Feature indices mirror FeatureExtractor.kt:
 *   0=url_length  4=num_dots  5=num_hyphens  8=num_at_signs
 *   17=is_https  18=is_ip_address  19=num_subdomains
 *   20=has_suspicious_tld  22=phishing_keyword_count  23=brand_keyword_count
 *   24=has_url_shortener  26=has_port_in_url  27=has_double_slash_in_path
 *   32=has_hex_encoding  33=consecutive_digits_in_domain  34=has_tld_in_path
 */
object XAIEngine {

    // Rule fires when: invert=false → feature > threshold | invert=true → feature <= threshold
    // Score is the fixed weight (not multiplied by raw value — prevents count features dominating).
    private data class Rule(
        val featIdx: Int,
        val threshold: Float,
        val weight: Float,
        val reason: String,
        val invert: Boolean = false,
    )

    private val RULES = listOf(
        Rule(8,  0f,  5.0f, "This link contains an '@' sign — a trick used to hide the real website address"),
        Rule(20, 0f,  4.5f, "This link has a suspicious web address ending (like .xyz or .tk) that is commonly used for scams"),
        Rule(22, 0f,  4.0f, "This link contains suspicious words like 'login', 'verify', or 'secure' — banks never ask for passwords via links"),
        Rule(23, 0f,  3.8f, "This link pretends to be a well-known brand or bank to trick you"),
        Rule(18, 0f,  3.5f, "This link goes directly to an IP address instead of a real website name — this is very unusual and suspicious"),
        Rule(24, 0f,  3.2f, "This is a shortened link that hides the real destination"),
        Rule(0,  80f, 2.8f, "This link is unusually long — scammers use long links to confuse people"),
        Rule(4,  4f,  2.5f, "This link has too many dots, which is a common trick used in phishing"),
        Rule(5,  3f,  2.3f, "This link has many hyphens, which scammers use to make fake sites look real"),
        Rule(34, 0f,  2.0f, "This link has a real website address hidden inside a longer fake one"),
        Rule(17, 0f,  1.8f, "This link does not use a secure connection (no padlock) — your information could be stolen", invert = true),
        Rule(33, 2f,  1.5f, "This link contains lots of numbers in the website address, which is unusual for real websites"),
        Rule(32, 0f,  1.3f, "This link uses special encoded characters to hide its true destination"),
        Rule(26, 0f,  1.2f, "This link uses an unusual port number, which is not normal for real websites"),
        Rule(27, 0f,  1.0f, "This link has an unusual double-slash in the path, which may indicate a redirect trick"),
        Rule(19, 2f,  0.9f, "This link has many sub-addresses, which can be used to disguise a fake website"),
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
            val triggered = if (rule.invert) value <= rule.threshold else value > rule.threshold
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
