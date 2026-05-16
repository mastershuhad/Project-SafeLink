package com.safelink.ml

data class FusionResult(
    val verdict: Verdict,
    val confidence: Float,
    val cnnScore: Float,        // CNN p_malicious
    val bertScore: Float,       // URLBert p_phishing
    val anomalyMse: Float,
    val isAnomaly: Boolean,
    val reason: String,
)

enum class Verdict { SAFE, WARNING, MALICIOUS, BLOCKED, NO_INTERNET }

/**
 * Five-rule priority fusion engine — the academic core of SafeLink.
 *
 * Inputs:
 *   cnnProbs  FloatArray(3)  — [p_safe, p_warning, p_malicious] from CNN+Dense
 *   bertScore Float          — p_phishing from URLBert
 *   anomaly   AnomalyResult  — from AutoencoderDetector
 *
 * Rules (evaluated in priority order):
 *   0. Hard structural pre-rule — hyphens ≥2 AND brand signal → MALICIOUS
 *   1. CNN confidence > 0.85 → trust CNN (with URLBert override and feature gates)
 *   2. |CNN_malicious − BERT_phishing| > 0.4 → WARNING (zero-day signal)
 *   3. Autoencoder anomaly AND CNN confidence < 0.6 → WARNING
 *   4. Both models agree (same class) → average → SAFE or MALICIOUS
 *   5. Default: CNN×0.70 + URLBert×0.30 weighted blend
 *
 * Feature indices (22-feature set, PRD v5.1):
 *   4  num_hyphens        9  has_at_in_url      13 is_suspicious_tld
 *   6  num_subdomains     8  has_ip_host         18 min_brand_distance
 *   10 has_homoglyphs    11  has_hex_encoding    19 brand_in_subdomain
 *   12 is_url_shortener  21  has_punycode        15 special_char_ratio
 */
object FusionEngine {

    private const val CNN_HIGH_CONFIDENCE       = 0.85f
    private const val CNN_BERT_OVERRIDE_LIMIT   = 0.88f
    private const val MODEL_DIVERGENCE_THRESHOLD = 0.4f
    private const val CNN_LOW_CONFIDENCE        = 0.6f
    private const val SAFE_THRESHOLD            = 0.5f
    private const val BLEND_MALICIOUS_THRESHOLD = 0.55f
    private const val BERT_CONFIDENT_BENIGN     = 0.12f
    private const val BERT_CONFIDENT_PHISHING   = 0.88f

    const val MALICIOUS_CONFIDENCE_THRESHOLD = 0.90f

    // Structural phishing feature indices (22-feature set)
    //   9  = has_at_in_url         8  = has_ip_host
    //   13 = is_suspicious_tld    19  = brand_in_subdomain
    //   12 = is_url_shortener     11  = has_hex_encoding
    //   10 = has_homoglyphs       21  = has_punycode
    private val PHISHING_FEAT_IDX = intArrayOf(9, 8, 13, 19, 12, 11, 10, 21)

    private val STRUCT_RISK_WEIGHTS = mapOf(
        9  to 5.0f,   // has_at_in_url
        8  to 4.0f,   // has_ip_host
        13 to 4.5f,   // is_suspicious_tld
        19 to 4.5f,   // brand_in_subdomain
        12 to 3.2f,   // is_url_shortener
        11 to 1.3f,   // has_hex_encoding
        10 to 4.0f,   // has_homoglyphs
        21 to 3.5f,   // has_punycode
    )

    // Rule 0 — hyphen-stuffed brand impersonation
    private const val R0_HYPHENS_MIN = 2

    /**
     * Returns true when min_brand_distance (18) indicates typosquatting (distance 1–3).
     * Distance 0 = exact brand token match; distance 1–3 = suspicious lookalike.
     */
    private fun isBrandDistanceSuspicious(rawFeatures: FloatArray): Boolean {
        val dist = rawFeatures.getOrElse(18) { 99f }
        return dist in 1f..3f
    }

    /**
     * brand_in_subdomain (19) is always structural by definition —
     * a brand appearing in the subdomain IS direct impersonation.
     */
    private fun isBrandKwStructural(rawFeatures: FloatArray): Boolean {
        return rawFeatures.getOrElse(19) { 0f } > 0f
    }

    /**
     * Returns true when ALL critical phishing structural features are zero
     * AND min_brand_distance is not in the typosquatting range.
     * Indicates models are firing on URL character/token patterns alone.
     */
    fun allPhishingClean(rawFeatures: FloatArray): Boolean {
        if (isBrandDistanceSuspicious(rawFeatures)) return false
        return PHISHING_FEAT_IDX.all { idx ->
            idx >= rawFeatures.size || rawFeatures[idx] == 0f
        }
    }

    /**
     * Weighted sum of active phishing-structural features.
     * Returns 0.0 when there is zero structural evidence of phishing.
     */
    fun structuralRisk(rawFeatures: FloatArray): Float {
        val base = STRUCT_RISK_WEIGHTS.entries.sumOf { (idx, w) ->
            if (idx >= rawFeatures.size || rawFeatures[idx] == 0f) 0.0
            else w.toDouble()
        }.toFloat()
        return if (isBrandDistanceSuspicious(rawFeatures)) base + 3.8f else base
    }

    fun fuse(
        cnnProbs: FloatArray,
        bertScore: Float,
        anomaly: AnomalyResult,
        rawFeatures: FloatArray? = null,
    ): FusionResult {
        val cnnMalicious  = cnnProbs[2]
        val cnnSafe       = cnnProbs[0]
        val cnnConfidence = maxOf(cnnSafe, cnnMalicious)

        // --- Rule 0: Hard structural pre-rule — hyphen-stuffed brand impersonation ---
        // A hostname with ≥2 hyphens + brand signal is a textbook phishing domain.
        // No model score can legitimately override this.
        if (rawFeatures != null) {
            val numHyphens    = rawFeatures.getOrElse(4)  { 0f }   // num_hyphens
            val brandInSubdom = rawFeatures.getOrElse(19) { 0f }   // brand_in_subdomain
            val minBrandDist  = rawFeatures.getOrElse(18) { 99f }  // min_brand_distance
            val brandSignal   = brandInSubdom >= 1f || minBrandDist in 0f..2f
            if (numHyphens >= R0_HYPHENS_MIN && brandSignal) {
                val brandDetail = if (brandInSubdom >= 1f) "brand in subdomain"
                                  else "brand distance=${String.format("%.1f", minBrandDist)}"
                return FusionResult(
                    verdict    = Verdict.MALICIOUS,
                    confidence = 0.97f,
                    cnnScore   = cnnMalicious,
                    bertScore  = bertScore,
                    anomalyMse = anomaly.mse,
                    isAnomaly  = anomaly.isAnomaly,
                    reason     = "Rule 0: Hyphen-stuffed brand impersonation — " +
                                 "hyphens=${numHyphens.toInt()}, $brandDetail",
                )
            }
        }

        // --- Rule 1: High CNN confidence ---
        if (cnnConfidence > CNN_HIGH_CONFIDENCE) {
            if (cnnMalicious > cnnSafe) {
                if (bertScore < BERT_CONFIDENT_BENIGN) {
                    if (cnnMalicious < CNN_BERT_OVERRIDE_LIMIT) {
                        return FusionResult(
                            verdict    = Verdict.SAFE,
                            confidence = 1f - bertScore,
                            cnnScore   = cnnMalicious,
                            bertScore  = bertScore,
                            anomalyMse = anomaly.mse,
                            isAnomaly  = anomaly.isAnomaly,
                            reason     = "Rule 1: URLBert overrides CNN — strongly benign (BERT=${(bertScore * 100).toInt()}%)",
                        )
                    }
                } else if (bertScore < 0.5f) {
                    // CNN fires high but BERT leans safe — if ALL structural phishing features
                    // are zero, CNN is reacting to URL character patterns only. Reduce to SAFE.
                    if (rawFeatures != null && allPhishingClean(rawFeatures)) {
                        return FusionResult(
                            verdict    = Verdict.SAFE,
                            confidence = maxOf(0.5f, 1f - bertScore),
                            cnnScore   = cnnMalicious,
                            bertScore  = bertScore,
                            anomalyMse = anomaly.mse,
                            isAnomaly  = anomaly.isAnomaly,
                            reason     = "Rule 1: CNN fires on URL patterns only — BERT safe, no structural phishing evidence (BERT=${(bertScore * 100).toInt()}%)",
                        )
                    }
                    return FusionResult(
                        verdict    = Verdict.WARNING,
                        confidence = 0.65f,
                        cnnScore   = cnnMalicious,
                        bertScore  = bertScore,
                        anomalyMse = anomaly.mse,
                        isAnomaly  = anomaly.isAnomaly,
                        reason     = "Rule 1: CNN-URLBert disagreement — CNN malicious but URLBert safe (BERT=${(bertScore * 100).toInt()}%)",
                    )
                }
                // Feature-nullity gate: CNN + URLBert both fire but all structural features are
                // zero → both models reacting to character/token patterns only. Cap to WARNING.
                if (rawFeatures != null && allPhishingClean(rawFeatures) && bertScore <= BERT_CONFIDENT_PHISHING) {
                    return FusionResult(
                        verdict    = Verdict.WARNING,
                        confidence = 0.65f,
                        cnnScore   = cnnMalicious,
                        bertScore  = bertScore,
                        anomalyMse = anomaly.mse,
                        isAnomaly  = anomaly.isAnomaly,
                        reason     = "Rule 1b: pattern-only signal — no structural phishing evidence",
                    )
                }
            }
            val verdict = if (cnnMalicious > cnnSafe) Verdict.MALICIOUS else Verdict.SAFE
            return FusionResult(
                verdict    = verdict,
                confidence = cnnConfidence,
                cnnScore   = cnnMalicious,
                bertScore  = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly  = anomaly.isAnomaly,
                reason     = "Rule 1: CNN high confidence (${(cnnConfidence * 100).toInt()}%)",
            )
        }

        // --- Rule 2: Model divergence — zero-day signal ---
        val divergence    = kotlin.math.abs(cnnMalicious - bertScore)
        val bertUncertain = bertScore in BERT_CONFIDENT_BENIGN..BERT_CONFIDENT_PHISHING
        val cnnOverride   = cnnMalicious > 0.60f && bertScore < BERT_CONFIDENT_BENIGN && divergence > 0.55f
        val r2ShouldWarn  = rawFeatures == null || !allPhishingClean(rawFeatures) || cnnMalicious >= 0.55f
        if (divergence > MODEL_DIVERGENCE_THRESHOLD && (bertUncertain || cnnOverride) && r2ShouldWarn) {
            return FusionResult(
                verdict    = Verdict.WARNING,
                confidence = 0.65f,
                cnnScore   = cnnMalicious,
                bertScore  = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly  = anomaly.isAnomaly,
                reason     = "Rule 2: Model divergence — possible zero-day (CNN=${(cnnMalicious * 100).toInt()}%, BERT=${(bertScore * 100).toInt()}%)",
            )
        }

        // --- Rule 3: Autoencoder anomaly + low CNN confidence ---
        if (anomaly.isAnomaly && cnnConfidence < CNN_LOW_CONFIDENCE) {
            return FusionResult(
                verdict    = Verdict.WARNING,
                confidence = 0.60f,
                cnnScore   = cnnMalicious,
                bertScore  = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly  = true,
                reason     = "Rule 3: Anomaly detected (MSE=${String.format("%.4f", anomaly.mse)}) with low model confidence",
            )
        }

        // --- Rule 4: Both models agree ---
        val cnnSaysMalicious  = cnnMalicious > SAFE_THRESHOLD
        val bertSaysMalicious = bertScore > SAFE_THRESHOLD
        if (cnnSaysMalicious == bertSaysMalicious) {
            val avgMalicious = (cnnMalicious + bertScore) / 2f
            val verdict      = if (avgMalicious > SAFE_THRESHOLD) Verdict.MALICIOUS else Verdict.SAFE
            val confidence   = if (verdict == Verdict.MALICIOUS)
                maxOf(cnnMalicious, bertScore)
            else
                maxOf(1f - cnnMalicious, 1f - bertScore)
            // Structural SAFE override: both models agree safe but high structural risk → WARNING
            if (verdict == Verdict.SAFE && rawFeatures != null && structuralRisk(rawFeatures) >= 3.5f) {
                return FusionResult(
                    verdict    = Verdict.WARNING,
                    confidence = 0.70f,
                    cnnScore   = cnnMalicious,
                    bertScore  = bertScore,
                    anomalyMse = anomaly.mse,
                    isAnomaly  = anomaly.isAnomaly,
                    reason     = "Rule 4s: models agree safe but high structural risk (${String.format("%.1f", structuralRisk(rawFeatures))})",
                )
            }
            return FusionResult(
                verdict    = verdict,
                confidence = confidence,
                cnnScore   = cnnMalicious,
                bertScore  = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly  = anomaly.isAnomaly,
                reason     = "Rule 4: Models agree — averaged score",
            )
        }

        // --- Rule 5: Weighted blend (default) ---
        val blended = cnnMalicious * 0.70f + bertScore * 0.30f
        val verdict  = if (blended > BLEND_MALICIOUS_THRESHOLD) Verdict.MALICIOUS else Verdict.SAFE
        val confidence = if (verdict == Verdict.MALICIOUS) blended else (1f - blended)
        // Structural SAFE override — same check for blend path
        if (verdict == Verdict.SAFE && rawFeatures != null && structuralRisk(rawFeatures) >= 3.5f) {
            return FusionResult(
                verdict    = Verdict.WARNING,
                confidence = 0.70f,
                cnnScore   = cnnMalicious,
                bertScore  = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly  = anomaly.isAnomaly,
                reason     = "Rule 5s: blend safe but high structural risk (${String.format("%.1f", structuralRisk(rawFeatures))})",
            )
        }
        return FusionResult(
            verdict    = verdict,
            confidence = confidence,
            cnnScore   = cnnMalicious,
            bertScore  = bertScore,
            anomalyMse = anomaly.mse,
            isAnomaly  = anomaly.isAnomaly,
            reason     = "Rule 5: Weighted blend CNN×0.70 + BERT×0.30",
        )
    }
}
