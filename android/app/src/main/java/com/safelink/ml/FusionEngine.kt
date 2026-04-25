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
 *   1. CNN confidence > 0.85  → trust CNN directly
 *   2. |CNN_malicious − BERT_phishing| > 0.4  → WARNING (zero-day signal)
 *   3. Autoencoder anomaly AND CNN confidence < 0.6  → WARNING
 *   4. Both models agree (same class)  → average → SAFE or MALICIOUS
 *   5. Default: CNN×0.6 + URLBert×0.4 weighted blend
 */
object FusionEngine {

    private const val CNN_HIGH_CONFIDENCE = 0.85f
    private const val MODEL_DIVERGENCE_THRESHOLD = 0.4f
    private const val CNN_LOW_CONFIDENCE = 0.6f
    private const val SAFE_THRESHOLD = 0.5f
    // URLBert confidence bounds — when bert is outside [LOW, HIGH], it is highly
    // confident and should not be overridden by the divergence rule.
    private const val BERT_CONFIDENT_BENIGN   = 0.12f   // below → strongly benign
    private const val BERT_CONFIDENT_PHISHING = 0.88f   // above → strongly phishing

    fun fuse(cnnProbs: FloatArray, bertScore: Float, anomaly: AnomalyResult): FusionResult {
        val cnnMalicious = cnnProbs[2]
        val cnnSafe = cnnProbs[0]
        val cnnConfidence = maxOf(cnnSafe, cnnMalicious)

        // --- Rule 1: High CNN confidence ---
        if (cnnConfidence > CNN_HIGH_CONFIDENCE) {
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
        //   bert < BERT_CONFIDENT_BENIGN  → URLBert strongly says safe   → trust it, skip WARNING
        //   bert > BERT_CONFIDENT_PHISHING → URLBert strongly says phishing → fall to Rule 4/5 → MALICIOUS
        val divergence = kotlin.math.abs(cnnMalicious - bertScore)
        val bertUncertain = bertScore in BERT_CONFIDENT_BENIGN..BERT_CONFIDENT_PHISHING
        if (divergence > MODEL_DIVERGENCE_THRESHOLD && bertUncertain) {
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
        val blended = cnnMalicious * 0.6f + bertScore * 0.4f
        val verdict = if (blended > SAFE_THRESHOLD) Verdict.MALICIOUS else Verdict.SAFE
        val confidence = if (verdict == Verdict.MALICIOUS) blended else (1f - blended)
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
