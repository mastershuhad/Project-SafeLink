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
 *   1. CNN confidence > 0.85:
 *        CNN=MALICIOUS + URLBert strongly safe (<0.12) → SAFE   (URLBert overrides)
 *        CNN=MALICIOUS + URLBert mildly safe  (<0.50) → WARNING (disagreement)
 *        CNN=MALICIOUS + URLBert agrees       (≥0.50) → MALICIOUS
 *        CNN=SAFE                             (any)   → SAFE
 *   2. |CNN_malicious − BERT_phishing| > 0.4  → WARNING (zero-day signal)
 *   3. Autoencoder anomaly AND CNN confidence < 0.6  → WARNING
 *   4. Both models agree (same class)  → average → SAFE or MALICIOUS
 *   5. Default: CNN×0.6 + URLBert×0.4 weighted blend
 */
object FusionEngine {

    private const val CNN_HIGH_CONFIDENCE = 0.85f
    // Above this, CNN is too confident to be overridden by URLBert
    private const val CNN_BERT_OVERRIDE_LIMIT = 0.88f
    private const val MODEL_DIVERGENCE_THRESHOLD = 0.4f
    private const val CNN_LOW_CONFIDENCE = 0.6f
    private const val SAFE_THRESHOLD = 0.5f
    // Rule 5 blend path uses a higher threshold to reduce false positives
    // on URLs where CNN leans safe but URLBert is uncertain.
    // Raised from 0.50 -> 0.55: blend must cross 55% malicious to reach MALICIOUS verdict.
    private const val BLEND_MALICIOUS_THRESHOLD = 0.55f
    // URLBert confidence bounds
    private const val BERT_CONFIDENT_BENIGN   = 0.12f
    private const val BERT_CONFIDENT_PHISHING = 0.88f

    /**
     * Minimum confidence required to show MALICIOUS to the user.
     * Below this threshold the verdict is downgraded to WARNING so the user
     * is alerted without being shown an overly alarming verdict.
     * MALICIOUS is reserved for L0-blocklist hits and very high-confidence predictions.
     */
    const val MALICIOUS_CONFIDENCE_THRESHOLD = 0.90f

    // ── Option A/E: Phishing-structural feature indices ───────────────────────
    // These are the concrete structural signals that distinguish real phishing
    // from a URL that merely looks suspicious to character/token pattern models.
    // Indices match FeatureExtractor output order (same as Python pipeline).
    //   8  = num_at_signs          18 = is_ip_address
    //  20  = has_suspicious_tld    22 = phishing_keyword_count
    //  23  = brand_keyword_count   24 = has_url_shortener
    //  32  = has_hex_encoding      34 = has_subdomain_of_trusted
    private val PHISHING_FEAT_IDX = intArrayOf(8, 18, 20, 22, 23, 24, 32, 34)
    private val STRUCT_RISK_WEIGHTS = mapOf(
        8 to 5.0f, 18 to 4.0f, 20 to 4.5f, 22 to 4.0f,
        23 to 3.8f, 24 to 3.2f, 32 to 1.3f, 34 to 3.5f,
    )

    /** Option E: minimum weighted structural-risk score to sustain a MALICIOUS verdict. */
    const val STRUCTURAL_RISK_MIN = 1.0f

    // Rule 0 thresholds — hyphen-stuffed brand impersonation hard trigger
    private const val R0_HYPHENS_MIN       = 2   // ≥2 hyphens in host
    private const val R0_PHISH_KEYWORDS_MIN = 2f  // ≥2 phishing keywords (from host hyphens or path)
    private const val R0_BRAND_KEYWORDS_MIN = 1f  // ≥1 brand keyword in host

    /**
     * Option A helper: returns true when every critical phishing feature is zero.
     * Indicates the models are firing on URL character/token patterns alone.
     *
     * phishing_keyword_count (22) and brand_keyword_count (23) are treated as
     * "clean" when num_hyphens (5) = 0 AND has_suspicious_tld (20) = 0 — a keyword
     * appearing in a clean subdomain (e.g. login.microsoftonline.com) is not
     * structural evidence without accompanying hyphen or TLD abuse.
     */
    fun allPhishingClean(rawFeatures: FloatArray): Boolean {
        val hasHyphens      = rawFeatures.getOrElse(5)  { 0f } > 0f
        val hasSuspiciousTld = rawFeatures.getOrElse(20) { 0f } > 0f
        return PHISHING_FEAT_IDX.all { idx ->
            if (idx >= rawFeatures.size || rawFeatures[idx] == 0f) return@all true
            // Phishing keywords (22) only count as structural evidence with hyphens or suspicious TLD.
            // Brand keywords (23) always count — a brand name in a non-whitelisted domain is
            // inherently suspicious regardless of URL structure (catches TLD substitution attacks).
            if (idx == 22 && !hasHyphens && !hasSuspiciousTld) return@all true
            false
        }
    }

    /**
     * Option E helper: weighted sum of active phishing-structural features.
     * Returns 0.0 when there is zero structural evidence of phishing.
     *
     * Same keyword-gating as allPhishingClean: keywords (22, 23) only contribute
     * weight when hyphens or a suspicious TLD are also present.
     */
    fun structuralRisk(rawFeatures: FloatArray): Float {
        val hasHyphens       = rawFeatures.getOrElse(5)  { 0f } > 0f
        val hasSuspiciousTld = rawFeatures.getOrElse(20) { 0f } > 0f
        return STRUCT_RISK_WEIGHTS.entries.sumOf { (idx, w) ->
            if (idx >= rawFeatures.size || rawFeatures[idx] == 0f) return@sumOf 0.0
            // Phishing keywords (22) only contribute weight with hyphens or suspicious TLD.
            // Brand keywords (23) always contribute — TLD substitution has no hyphens.
            if (idx == 22 && !hasHyphens && !hasSuspiciousTld) return@sumOf 0.0
            w.toDouble()
        }.toFloat()
    }

    fun fuse(cnnProbs: FloatArray, bertScore: Float, anomaly: AnomalyResult, rawFeatures: FloatArray? = null): FusionResult {
        val cnnMalicious = cnnProbs[2]
        val cnnSafe = cnnProbs[0]
        val cnnConfidence = maxOf(cnnSafe, cnnMalicious)

        // --- Rule 0: Hard structural pre-rule — hyphen-stuffed brand impersonation ---
        // A hostname with ≥2 hyphens + ≥2 phishing keywords + ≥1 brand keyword is a
        // textbook phishing domain (e.g. secure-login-paypal-verification.com).
        // No model score can legitimately override this — short-circuit to MALICIOUS.
        if (rawFeatures != null) {
            val numHyphens    = rawFeatures.getOrElse(5)  { 0f }
            val phishKwCount  = rawFeatures.getOrElse(22) { 0f }
            val brandKwCount  = rawFeatures.getOrElse(23) { 0f }
            if (numHyphens >= R0_HYPHENS_MIN &&
                phishKwCount >= R0_PHISH_KEYWORDS_MIN &&
                brandKwCount >= R0_BRAND_KEYWORDS_MIN
            ) {
                return FusionResult(
                    verdict      = Verdict.MALICIOUS,
                    confidence   = 0.97f,
                    cnnScore     = cnnMalicious,
                    bertScore    = bertScore,
                    anomalyMse   = anomaly.mse,
                    isAnomaly    = anomaly.isAnomaly,
                    reason       = "Rule 0: Hyphen-stuffed brand impersonation — " +
                                   "hyphens=${numHyphens.toInt()}, " +
                                   "phishKeywords=${phishKwCount.toInt()}, " +
                                   "brandKeywords=${brandKwCount.toInt()}",
                )
            }
        }

        // --- Rule 1: High CNN confidence ---
        if (cnnConfidence > CNN_HIGH_CONFIDENCE) {
            if (cnnMalicious > cnnSafe) {
                if (bertScore < BERT_CONFIDENT_BENIGN) {
                    // URLBert override: only allowed when CNN is not too confident.
                    // Above CNN_BERT_OVERRIDE_LIMIT (0.88) the CNN signal is strong enough
                    // that URLBert's character-pattern assessment should not dismiss it.
                    if (cnnMalicious < CNN_BERT_OVERRIDE_LIMIT) {
                        return FusionResult(
                            verdict = Verdict.SAFE,
                            confidence = 1f - bertScore,
                            cnnScore = cnnMalicious,
                            bertScore = bertScore,
                            anomalyMse = anomaly.mse,
                            isAnomaly = anomaly.isAnomaly,
                            reason = "Rule 1: URLBert overrides CNN — strongly benign (BERT=${(bertScore * 100).toInt()}%)",
                        )
                    }
                    // CNN too confident to be overridden — fall through to MALICIOUS
                } else if (bertScore < 0.5f) {
                    // Option A-extended: CNN fires high but BERT leans safe — if ALL structural
                    // phishing features are zero, CNN is reacting to URL character patterns only
                    // (e.g. #/login in a SPA route). Reduce to SAFE rather than WARNING.
                    if (rawFeatures != null && allPhishingClean(rawFeatures)) {
                        return FusionResult(
                            verdict = Verdict.SAFE,
                            confidence = maxOf(0.5f, 1f - bertScore),
                            cnnScore = cnnMalicious,
                            bertScore = bertScore,
                            anomalyMse = anomaly.mse,
                            isAnomaly = anomaly.isAnomaly,
                            reason = "Rule 1: CNN fires on URL patterns only — BERT safe, no structural phishing evidence (BERT=${(bertScore * 100).toInt()}%)",
                        )
                    }
                    return FusionResult(
                        verdict = Verdict.WARNING,
                        confidence = 0.65f,
                        cnnScore = cnnMalicious,
                        bertScore = bertScore,
                        anomalyMse = anomaly.mse,
                        isAnomaly = anomaly.isAnomaly,
                        reason = "Rule 1: CNN-URLBert disagreement — CNN malicious but URLBert safe (BERT=${(bertScore * 100).toInt()}%)",
                    )
                }
                // ── Option A: Feature-Nullity Gate ────────────────────────────────
                // CNN is high-conf MALICIOUS and URLBert also agrees (bert ≥ 0.5).
                // But if ALL critical phishing features are zero, both models are
                // firing on URL character/token patterns alone (e.g. repeated product
                // token in path, hyphens in slug).  Cap to WARNING — never assert
                // MALICIOUS without at least one structural evidence feature.
                //
                // Exception: when URLBert is also very confident (>0.90), two
                // independent models both at 90%+ is itself strong evidence — bypass
                // the structural gate. URLBert reads URLs as language and catches
                // typosquatting (app1e, paypa1) that structural features miss entirely.
                if (rawFeatures != null && allPhishingClean(rawFeatures) && bertScore <= BERT_CONFIDENT_PHISHING) {
                    return FusionResult(
                        verdict = Verdict.WARNING,
                        confidence = 0.65f,
                        cnnScore = cnnMalicious,
                        bertScore = bertScore,
                        anomalyMse = anomaly.mse,
                        isAnomaly = anomaly.isAnomaly,
                        reason = "Rule 1b: pattern-only signal — no structural phishing evidence",
                    )
                }
                // ──────────────────────────────────────────────────────────────────
            }
            val verdict = if (cnnMalicious > cnnSafe) Verdict.MALICIOUS else Verdict.SAFE
            return FusionResult(
                verdict = verdict,
                confidence = cnnConfidence,
                cnnScore = cnnMalicious,
                bertScore = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly = anomaly.isAnomaly,
                reason = "Rule 1: CNN high confidence (${(cnnConfidence * 100).toInt()}%)",
            )
        }

        // --- Rule 2: Model divergence — zero-day signal ---
        // Guard: skip when URLBert is highly confident in either direction.
        // Additional guard (mirrors Python Rule 2 fix): skip WARNING when CNN is
        // low-confidence (< 0.55) AND all phishing features are zero — this prevents
        // false WARNINGs on clean domains where URLBert is merely uncertain about
        // the URL character pattern (e.g. mobile retailer homepages).
        val divergence = kotlin.math.abs(cnnMalicious - bertScore)
        val bertUncertain = bertScore in BERT_CONFIDENT_BENIGN..BERT_CONFIDENT_PHISHING
        val cnnOverride = cnnMalicious > 0.60f && bertScore < BERT_CONFIDENT_BENIGN && divergence > 0.55f
        val r2ShouldWarn = rawFeatures == null || !allPhishingClean(rawFeatures) || cnnMalicious >= 0.55f
        if (divergence > MODEL_DIVERGENCE_THRESHOLD && (bertUncertain || cnnOverride) && r2ShouldWarn) {
            return FusionResult(
                verdict = Verdict.WARNING,
                confidence = 0.65f,
                cnnScore = cnnMalicious,
                bertScore = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly = anomaly.isAnomaly,
                reason = "Rule 2: Model divergence — possible zero-day (CNN=${(cnnMalicious * 100).toInt()}%, BERT=${(bertScore * 100).toInt()}%)",
            )
        }

        // --- Rule 3: Autoencoder anomaly + low CNN confidence ---
        if (anomaly.isAnomaly && cnnConfidence < CNN_LOW_CONFIDENCE) {
            return FusionResult(
                verdict = Verdict.WARNING,
                confidence = 0.70f,
                cnnScore = cnnMalicious,
                bertScore = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly = true,
                reason = "Rule 3: Anomaly detected (MSE=${String.format("%.4f", anomaly.mse)}) with low model confidence",
            )
        }

        // --- Rule 4: Both models agree ---
        val cnnSaysMalicious = cnnMalicious > SAFE_THRESHOLD
        val bertSaysMalicious = bertScore > SAFE_THRESHOLD
        if (cnnSaysMalicious == bertSaysMalicious) {
            val avgMalicious = (cnnMalicious + bertScore) / 2f
            val verdict = if (avgMalicious > SAFE_THRESHOLD) Verdict.MALICIOUS else Verdict.SAFE
            val confidence = if (verdict == Verdict.MALICIOUS) avgMalicious else (1f - avgMalicious)
            // Structural SAFE override: both models agree safe but high structural risk
            // (hyphens + phishing keywords + brand keyword) — force WARNING
            if (verdict == Verdict.SAFE && rawFeatures != null && structuralRisk(rawFeatures) >= 3.5f) {
                return FusionResult(
                    verdict = Verdict.WARNING,
                    confidence = 0.70f,
                    cnnScore = cnnMalicious,
                    bertScore = bertScore,
                    anomalyMse = anomaly.mse,
                    isAnomaly = anomaly.isAnomaly,
                    reason = "Rule 4s: models agree safe but high structural risk (${String.format("%.1f", structuralRisk(rawFeatures))})",
                )
            }
            return FusionResult(
                verdict = verdict,
                confidence = confidence,
                cnnScore = cnnMalicious,
                bertScore = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly = anomaly.isAnomaly,
                reason = "Rule 4: Models agree — averaged score",
            )
        }

        // --- Rule 5: Weighted blend (default) ---
        val blended = cnnMalicious * 0.70f + bertScore * 0.30f  // raised CNN weight to reduce BERT-driven FPs
        val verdict = if (blended > BLEND_MALICIOUS_THRESHOLD) Verdict.MALICIOUS else Verdict.SAFE
        val confidence = if (verdict == Verdict.MALICIOUS) blended else (1f - blended)
        // Structural SAFE override — same check for blend path
        if (verdict == Verdict.SAFE && rawFeatures != null && structuralRisk(rawFeatures) >= 3.5f) {
            return FusionResult(
                verdict = Verdict.WARNING,
                confidence = 0.70f,
                cnnScore = cnnMalicious,
                bertScore = bertScore,
                anomalyMse = anomaly.mse,
                isAnomaly = anomaly.isAnomaly,
                reason = "Rule 5s: blend safe but high structural risk (${String.format("%.1f", structuralRisk(rawFeatures))})",
            )
        }
        return FusionResult(
            verdict = verdict,
            confidence = confidence,
            cnnScore = cnnMalicious,
            bertScore = bertScore,
            anomalyMse = anomaly.mse,
            isAnomaly = anomaly.isAnomaly,
            reason = "Rule 5: Weighted blend CNN×0.6 + BERT×0.4",
        )
    }
}
