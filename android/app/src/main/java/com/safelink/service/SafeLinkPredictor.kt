package com.safelink.service

import com.safelink.App
import com.safelink.ml.AnomalyResult
import com.safelink.ml.FusionEngine
import com.safelink.ml.FusionResult
import com.safelink.ml.UrlTokenizer
import com.safelink.ml.FeatureExtractor
import com.safelink.ml.Verdict
import com.safelink.ml.XAIEngine
import com.safelink.ml.XAIResult
import com.safelink.network.DynamicWhitelist
import com.safelink.network.GeminiClient
import com.safelink.network.GoogleSafeBrowsingClient
import com.safelink.network.NetworkChecker
import com.safelink.network.NetworkUrlEvaluator
import com.safelink.network.RDAPClient
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

data class PredictionResult(
    val verdict: Verdict,
    val confidence: Float,
    val primaryReason: String,
    val allReasons: List<String>,
    val geminiExplanation: String,
    val cnnScore: Float,
    val bertScore: Float,
    val anomalyMse: Float,
    val domainAgeDays: Float,
    val layer: String,
    val matchedBrand: String?,
)

/**
 * Full four-layer prediction pipeline orchestrator.
 *
 * L0: Hard blocks  (blocklist, @ sign, brand impersonation, GSB post-SAFE)
 * L1: Trust paths  (whitelist, trusted TLD, private IP, dynamic whitelist)
 * L2: ML hybrid   (parallel CNN + AE + RDAP, sequential URLBert, fusion)
 * L3: Auto-trust   (dynamic whitelist promotion for confident SAFE results)
 */
class SafeLinkPredictor(
    private val networkChecker: NetworkChecker,
    private val rdapClient: RDAPClient,
    private val gsbClient: GoogleSafeBrowsingClient,
    private val geminiClient: GeminiClient,
    private val dynamicWhitelist: DynamicWhitelist,
) {

    // Known government/education TLDs that are inherently trusted
    private val TRUSTED_TLDS = setOf("gov", "edu", "mil", "ac", "gov.lk", "ac.lk", "edu.lk")

    private val BRAND_IMPERSONATION_BRANDS = setOf(
        "hnb", "sampath", "boc", "combank", "peoples", "dialog", "mobitel", "slt",
        "paypal", "amazon", "google", "facebook", "apple", "microsoft", "netflix",
    )

    suspend fun predict(url: String): PredictionResult = withContext(Dispatchers.Default) {

        // --- L0: Hard blocks ---

        // @-sign in URL (credential theft indicator)
        if ('@' in url) {
            return@withContext blocked(url, "URL contains '@' sign — a known phishing trick to hide the real destination", "L0-AT")
        }

        // Static blocklist
        val host = extractHost(url)
        if (host != null && App.blocklist.contains(host)) {
            return@withContext blocked(url, "This website is on the malware/phishing blocklist", "L0-BLOCKLIST")
        }

        // Brand impersonation check (domain contains brand keyword but is NOT the real domain)
        val brandImpersonation = checkBrandImpersonation(host, url)
        if (brandImpersonation != null) {
            return@withContext blocked(url, brandImpersonation, "L0-BRAND")
        }

        // --- Check network connectivity ---
        if (!networkChecker.isConnected()) {
            return@withContext PredictionResult(
                verdict = Verdict.NO_INTERNET,
                confidence = 1f,
                primaryReason = "No internet connection — cannot verify this link",
                allReasons = listOf("No internet connection"),
                geminiExplanation = "",
                cnnScore = 0f,
                bertScore = 0f,
                anomalyMse = 0f,
                domainAgeDays = -1f,
                layer = "L0-NO_INTERNET",
                matchedBrand = null,
            )
        }

        // --- L1: Trust fast paths ---

        // Static whitelist
        if (host != null && App.whitelist.contains(host)) {
            return@withContext safe(url, "This website is on the trusted list", "L1-WHITELIST")
        }

        // Trusted TLDs
        val tld = host?.substringAfterLast('.') ?: ""
        if (tld in TRUSTED_TLDS || host?.endsWith(".gov.lk") == true || host?.endsWith(".ac.lk") == true) {
            return@withContext safe(url, "This is a trusted government or education website", "L1-TRUSTED_TLD")
        }

        // Private IP / local network
        if (host != null) {
            val netResult = NetworkUrlEvaluator.evaluate(host, extractPath(url))
            when (netResult) {
                NetworkUrlEvaluator.Result.CLEAN ->
                    return@withContext safe(url, "This is a local network address", "L1-LOCAL_NETWORK")
                NetworkUrlEvaluator.Result.SUSPICIOUS ->
                    return@withContext PredictionResult(
                        verdict = Verdict.WARNING,
                        confidence = 0.75f,
                        primaryReason = "This local network link contains suspicious path words",
                        allReasons = listOf("Suspicious path on local network address"),
                        geminiExplanation = "",
                        cnnScore = 0f, bertScore = 0f, anomalyMse = 0f,
                        domainAgeDays = -1f, layer = "L1-LOCAL_SUSPICIOUS", matchedBrand = null,
                    )
                NetworkUrlEvaluator.Result.NOT_LOCAL -> { /* continue */ }
            }
        }

        // Dynamic whitelist (auto-trusted after 5 SAFE scans)
        if (host != null && dynamicWhitelist.isTrusted(host)) {
            return@withContext safe(url, "This website has been verified as safe multiple times", "L1-DYNAMIC_WHITELIST")
        }

        // --- L2: ML hybrid inference ---

        if (!App.modelsReady) {
            return@withContext PredictionResult(
                verdict = Verdict.WARNING,
                confidence = 0.5f,
                primaryReason = "Safety models are still loading — please wait a moment and try again",
                allReasons = listOf("Models not ready"),
                geminiExplanation = "",
                cnnScore = 0f, bertScore = 0f, anomalyMse = 0f,
                domainAgeDays = -1f, layer = "L2-MODELS_NOT_READY", matchedBrand = null,
            )
        }

        // Extract raw features
        val rawFeatures = FeatureExtractor.extract(url)

        // Launch RDAP and CNN in parallel
        val rdapDeferred: Deferred<Float> = async(Dispatchers.IO) {
            withTimeoutOrNull(150L) {
                rdapClient.getDomainAgeDays(url)
            } ?: -1f
        }

        val cnnDeferred: Deferred<FloatArray> = async(Dispatchers.Default) {
            // Fill domain_age_days = -1f for now (RDAP result applied below)
            val scaledFeatures = App.featureScaler.scale(rawFeatures)
            val seqInput = UrlTokenizer.encode(url)
            App.classifier.classify(seqInput, scaledFeatures)
        }

        val aeDeferred: Deferred<AnomalyResult> = async(Dispatchers.Default) {
            val scaledFeatures = App.featureScaler.scale(rawFeatures)
            App.autoencoderDetector.detect(scaledFeatures, rawFeatures[0])
        }

        // URLBert runs sequentially (heavier model, ~80-150ms)
        val bertScore = withContext(Dispatchers.Default) {
            App.bertClassifier.classify(url)
        }

        // Wait for parallel results
        val domainAgeDays = rdapDeferred.await()
        val cnnProbs = cnnDeferred.await()
        val anomalyResult = aeDeferred.await()

        // Re-scale with actual domain age if RDAP succeeded
        val finalScaledFeatures = if (domainAgeDays >= 0f) {
            rawFeatures[35] = domainAgeDays
            App.featureScaler.scale(rawFeatures)
        } else {
            App.featureScaler.scale(rawFeatures)
        }

        // Fusion
        val fusion = FusionEngine.fuse(cnnProbs, bertScore, anomalyResult)

        // XAI
        val xai = XAIEngine.explain(rawFeatures, App.knowledgeHub, url, fusion.verdict)

        // Gemini — only on WARNING
        val geminiExplanation = if (fusion.verdict == Verdict.WARNING) {
            withContext(Dispatchers.IO) {
                geminiClient.explainWarning(url, xai.primaryReason, xai.geminiContext)
            }
        } else ""

        // GSB — only on SAFE (conserve API quota)
        val finalVerdict: Verdict
        val finalLayer: String
        if (fusion.verdict == Verdict.SAFE) {
            val gsbFlagged = withContext(Dispatchers.IO) {
                gsbClient.isMalicious(url)
            }
            if (gsbFlagged == true) {
                finalVerdict = Verdict.MALICIOUS
                finalLayer = "L2-GSB"
            } else {
                finalVerdict = Verdict.SAFE
                finalLayer = "L2-ML"
            }
        } else {
            finalVerdict = fusion.verdict
            finalLayer = "L2-ML"
        }

        // --- L3: Auto-trust promotion ---
        if (finalVerdict == Verdict.SAFE && fusion.confidence > 0.90f && host != null) {
            dynamicWhitelist.recordSafeScan(host, fusion.confidence)
        }

        PredictionResult(
            verdict = finalVerdict,
            confidence = fusion.confidence,
            primaryReason = xai.primaryReason,
            allReasons = xai.allReasons,
            geminiExplanation = geminiExplanation,
            cnnScore = fusion.cnnScore,
            bertScore = fusion.bertScore,
            anomalyMse = fusion.anomalyMse,
            domainAgeDays = domainAgeDays,
            layer = finalLayer,
            matchedBrand = xai.matchedBrand,
        )
    }

    private fun extractHost(url: String): String? = try {
        val normalized = if ("://" !in url) "http://$url" else url
        android.net.Uri.parse(normalized).host?.lowercase()?.removePrefix("www.")
    } catch (e: Exception) { null }

    private fun extractPath(url: String): String = try {
        val normalized = if ("://" !in url) "http://$url" else url
        android.net.Uri.parse(normalized).path ?: ""
    } catch (e: Exception) { "" }

    private fun checkBrandImpersonation(host: String?, url: String): String? {
        if (host == null) return null
        val matched = App.knowledgeHub.findBrand(url)
        if (matched != null) {
            // If host IS one of the brand's legitimate domains, it's fine
            val isLegit = matched.domains.any { legit ->
                host == legit || host.endsWith(".$legit")
            }
            if (!isLegit) {
                return "This link pretends to be ${matched.displayName} — it is NOT the real website"
            }
        }
        return null
    }

    private fun safe(url: String, reason: String, layer: String) = PredictionResult(
        verdict = Verdict.SAFE, confidence = 1f,
        primaryReason = reason, allReasons = listOf(reason),
        geminiExplanation = "", cnnScore = 0f, bertScore = 0f,
        anomalyMse = 0f, domainAgeDays = -1f, layer = layer, matchedBrand = null,
    )

    private fun blocked(url: String, reason: String, layer: String) = PredictionResult(
        verdict = Verdict.BLOCKED, confidence = 1f,
        primaryReason = reason, allReasons = listOf(reason),
        geminiExplanation = "", cnnScore = 0f, bertScore = 0f,
        anomalyMse = 0f, domainAgeDays = -1f, layer = layer, matchedBrand = null,
    )
}
