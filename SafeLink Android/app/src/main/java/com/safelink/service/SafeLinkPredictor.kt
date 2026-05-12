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
import com.safelink.network.NetworkChecker
import com.safelink.network.NetworkUrlEvaluator
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

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
    private val geminiClient: GeminiClient,
    private val dynamicWhitelist: DynamicWhitelist,
) {

    // Known government/education TLDs that are inherently trusted
    private val TRUSTED_TLDS = setOf("gov", "edu", "mil", "ac", "gov.lk", "ac.lk", "edu.lk")

    // Option 1 — legitimate user-hosting platforms where both real sites and phishing coexist.
    // Models are biased against these due to training data; cap MALICIOUS → WARNING.
    private val USER_HOSTED_PLATFORMS = setOf(
        "wixsite.com", "weebly.com", "webflow.io", "wordpress.com",
        "blogspot.com", "squarespace.com", "sites.google.com",
        "github.io", "netlify.app", "vercel.app", "cargo.site",
    )

    // Option 2 — path words that strongly suggest personal/portfolio content, not phishing.
    // Only fires when the path exclusively contains such words (no phishing keywords present).
    private val SAFE_PATH_WORDS = setOf(
        "portfolio", "about", "blog", "resume", "cv", "gallery",
        "contact", "projects", "work", "services", "showcase",
    )

    private val BRAND_IMPERSONATION_BRANDS = setOf(
        "hnb", "sampath", "boc", "combank", "peoples", "dialog", "mobitel", "slt",
        "paypal", "amazon", "google", "facebook", "apple", "microsoft", "netflix",
    )

    suspend fun predict(url: String): PredictionResult = withContext(Dispatchers.Default) {

        // Ensure critical core assets (blocklist/whitelist/hub) are loaded
        if (!App.coreAssetsReady) {
            var waited = 0
            // Core assets are usually loaded in <1s
            while (!App.coreAssetsReady && waited < 5_000) {
                delay(100)
                waited += 100
            }
        }

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
        if (host != null && (App.whitelist.contains(host) || App.whitelist.any { wl -> host.endsWith(".$wl") })) {
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
            // Wait up to 15 s for background model loading; exit immediately if load failed
            var waited = 0
            while (!App.modelsReady && !App.modelsFailed && waited < 15_000) {
                delay(200)
                waited += 200
            }
            if (!App.modelsReady) {
                val reason = if (App.modelsFailed)
                    "Safety models could not be loaded — only blocklist protection is active"
                else
                    "Safety models are still initialising — please try again in a moment"
                return@withContext PredictionResult(
                    verdict = Verdict.WARNING,
                    confidence = 0f,
                    primaryReason = reason,
                    allReasons = listOf(reason),
                    geminiExplanation = "",
                    cnnScore = 0f, bertScore = 0f, anomalyMse = 0f,
                    domainAgeDays = -1f, layer = "L2-MODELS_NOT_READY", matchedBrand = null,
                )
            }
        }

        // Extract raw features
        val rawFeatures = FeatureExtractor.extract(url)
        val domainAgeDays = -1f  // RDAP removed — domain age not used

        // Launch CNN and Autoencoder in parallel
        val cnnDeferred: Deferred<FloatArray> = async(Dispatchers.Default) {
            val scaledFeatures = App.featureScaler.scale(rawFeatures)
            val seqInput = UrlTokenizer.encode(url)
            App.classifier.classify(seqInput, scaledFeatures)
        }

        val aeDeferred: Deferred<AnomalyResult> = async(Dispatchers.Default) {
            val ae = App.autoencoderDetector
            if (ae != null) {
                val scaledFeatures = App.featureScaler.scale(rawFeatures)
                ae.detect(scaledFeatures, rawFeatures[0])
            } else {
                AnomalyResult(mse = 0f, isAnomaly = false, category = "medium", threshold = 0.02f)
            }
        }

        // URLBert runs sequentially (heavier model, ~80-150ms)
        // Strip trailing slash before tokenizing — URLBert tokenizer is sensitive to it
        // and produces wildly different scores for "example.com/" vs "example.com"
        val bertScore = withContext(Dispatchers.Default) {
            App.bertClassifier?.classify(url.trimEnd('/')) ?: 0.5f
        }

        val cnnProbs = cnnDeferred.await()
        val anomalyResult = aeDeferred.await()

        // Fusion — pass rawFeatures to enable Option A feature-nullity gate
        var fusion = contextAdjust(url, rawFeatures, FusionEngine.fuse(cnnProbs, bertScore, anomalyResult, rawFeatures))

        // Option E: Structural Risk post-fusion cap
        // MALICIOUS but structural_risk == 0  → SAFE  (models fired on character/token patterns
        //   only — no concrete phishing features: no hyphens+keywords, no suspicious TLD,
        //   no brand SLD, no shortener, no IP, no @ sign).  Product slugs (xiaomi-15-5g),
        //   tech paths, and SPA fragments land here.
        // MALICIOUS but 0 < structural_risk < STRUCTURAL_RISK_MIN  → WARNING (minimal evidence).
        val structRisk = FusionEngine.structuralRisk(rawFeatures)
        if (fusion.verdict == Verdict.MALICIOUS && structRisk < FusionEngine.STRUCTURAL_RISK_MIN) {
            fusion = if (structRisk == 0f) {
                fusion.copy(
                    verdict = Verdict.SAFE,
                    confidence = 0.60f,
                    reason = "${fusion.reason} → SAFE (structural_risk=0, pattern-only signal)",
                )
            } else {
                fusion.copy(
                    verdict = Verdict.WARNING,
                    confidence = 0.65f,
                    reason = "${fusion.reason} → WARNING (structural_risk=${String.format("%.2f", structRisk)}, minimal evidence)",
                )
            }
        }

        // ── Confidence gate ────────────────────────────────────────────────────
        // MALICIOUS is reserved for L0-blocklist hits and very high-confidence
        // predictions (≥ 90%).  Below the threshold the verdict is downgraded to
        // WARNING so the user is alerted but not shown an overly alarming verdict.
        // Gemini explanation will fire automatically because verdict == WARNING.
        if (fusion.verdict == Verdict.MALICIOUS &&
            fusion.confidence < FusionEngine.MALICIOUS_CONFIDENCE_THRESHOLD
        ) {
            fusion = fusion.copy(
                verdict = Verdict.WARNING,
                reason  = "${fusion.reason} → WARNING (conf ${(fusion.confidence * 100).toInt()}% < 90% threshold)",
            )
        }

        // XAI
        val rawXai = XAIEngine.explain(rawFeatures, App.knowledgeHub, url, fusion.verdict)

        // For user-hosting platform WARNINGs, replace the generic feature reason with a
        // plain-language explanation that tells the user WHY this platform is risky.
        val userHostedPlatform = if (fusion.verdict == Verdict.WARNING && host != null) {
            USER_HOSTED_PLATFORMS.firstOrNull { p -> host != p && host.endsWith(".$p") }
        } else null
        val xai = if (userHostedPlatform != null) {
            val r = "This link is on $userHostedPlatform — a free hosting service where anyone " +
                    "can create pages, including scammers. Only open it if you trust who shared it."
            rawXai.copy(
                primaryReason = r,
                allReasons = listOf(r) + rawXai.allReasons.take(2),
                geminiContext = "User-hosting platform: $userHostedPlatform. Content is user-generated. ${rawXai.geminiContext}",
            )
        } else rawXai

        // Gemini — only on WARNING
        val geminiExplanation = if (fusion.verdict == Verdict.WARNING) {
            withContext(Dispatchers.IO) {
                geminiClient.explainWarning(url, xai.primaryReason, xai.geminiContext)
            }
        } else ""

        // --- L3: Auto-trust promotion ---
        if (fusion.verdict == Verdict.SAFE && fusion.confidence > 0.90f && host != null) {
            dynamicWhitelist.recordSafeScan(host, fusion.confidence)
        }

        PredictionResult(
            verdict = fusion.verdict,
            confidence = fusion.confidence,
            primaryReason = xai.primaryReason,
            allReasons = xai.allReasons,
            geminiExplanation = geminiExplanation,
            cnnScore = fusion.cnnScore,
            bertScore = fusion.bertScore,
            anomalyMse = fusion.anomalyMse,
            domainAgeDays = domainAgeDays,
            layer = "L2-ML",
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

    private fun contextAdjust(url: String, rawFeatures: FloatArray, fusion: FusionResult): FusionResult {
        val host = extractHost(url)

        // User-hosting platform subdomains: cap SAFE/WARNING to WARNING — anyone can publish here
        if (host != null) {
            val platform = USER_HOSTED_PLATFORMS.firstOrNull { p -> host != p && host.endsWith(".$p") }
            if (platform != null && (fusion.verdict == Verdict.SAFE || fusion.verdict == Verdict.WARNING)) {
                return fusion.copy(
                    verdict = Verdict.WARNING,
                    confidence = maxOf(fusion.confidence, 0.60f),
                    reason = "${fusion.reason} → user-hosting platform ($platform): content is user-generated",
                )
            }
        }

        if (fusion.verdict != Verdict.MALICIOUS) return fusion
        if (host == null) return fusion

        val path = extractPath(url).lowercase()

        // User-hosting platform — model bias runs high against these domains
        val isHostedPlatform = USER_HOSTED_PLATFORMS.any { p -> host == p || host.endsWith(".$p") }

        // Safe path words — only downgrade when NO phishing keywords are also present
        val phishingKwCount = rawFeatures.getOrElse(22) { 0f }
        val pathWords = path.split("/", "-", "_", ".").toSet()
        val hasSafePathWord = phishingKwCount == 0f && SAFE_PATH_WORDS.intersect(pathWords).isNotEmpty()

        if (!isHostedPlatform && !hasSafePathWord) return fusion

        val tags = mutableListOf<String>()
        if (isHostedPlatform) tags.add("user-hosting platform")
        if (hasSafePathWord) tags.add("safe path word")

        return fusion.copy(
            verdict = Verdict.WARNING,
            confidence = 0.60f,
            reason = "${fusion.reason} → capped to WARNING (${tags.joinToString(", ")})",
        )
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
