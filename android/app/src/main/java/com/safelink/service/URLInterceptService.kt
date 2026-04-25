package com.safelink.service

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.safelink.App
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import com.safelink.ml.Verdict
import com.safelink.network.DynamicWhitelist
import com.safelink.network.GeminiClient
import com.safelink.network.GoogleSafeBrowsingClient
import com.safelink.network.NetworkChecker
import com.safelink.network.RDAPClient
import com.safelink.ui.NoInternetPopupActivity
import com.safelink.ui.VerdictPopupActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.LinkedHashMap

class URLInterceptService : AccessibilityService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val predictor by lazy {
        SafeLinkPredictor(
            networkChecker = NetworkChecker(this),
            rdapClient = RDAPClient(),
            gsbClient = GoogleSafeBrowsingClient(),
            geminiClient = GeminiClient(),
            dynamicWhitelist = DynamicWhitelist(this),
        )
    }

    private val db by lazy { SafeLinkDatabase.getInstance(this) }

    // 3-second debounce — same URL won't be processed twice within 3s
    private val recentUrls = object : LinkedHashMap<String, Long>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Long>) = size > 50
    }
    private val DEBOUNCE_MS = 3000L

    private val URL_PATTERN = Regex(
        """https?://[^\s"'<>]+|www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s"'<>]*"""
    )

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!App.protectionEnabled) return
        if (event == null) return
        if (event.eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED &&
            event.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return

        val root = rootInActiveWindow ?: return
        extractUrls(root).forEach { url ->
            processUrl(url)
        }
        root.recycle()
    }

    override fun onInterrupt() {}

    private fun extractUrls(node: AccessibilityNodeInfo): List<String> {
        val found = mutableListOf<String>()
        extractUrlsRecursive(node, found, depth = 0)
        return found.distinct()
    }

    private fun extractUrlsRecursive(
        node: AccessibilityNodeInfo,
        result: MutableList<String>,
        depth: Int,
    ) {
        if (depth > 6) return  // Limit recursion depth

        val text = node.text?.toString() ?: ""
        val contentDesc = node.contentDescription?.toString() ?: ""

        for (source in listOf(text, contentDesc)) {
            URL_PATTERN.findAll(source).forEach { match ->
                result.add(match.value.trimEnd('.', ',', ')'))
            }
        }

        for (i in 0 until node.childCount) {
            node.getChild(i)?.let { child ->
                extractUrlsRecursive(child, result, depth + 1)
                child.recycle()
            }
        }
    }

    private fun processUrl(url: String) {
        val now = System.currentTimeMillis()
        synchronized(recentUrls) {
            val lastSeen = recentUrls[url]
            if (lastSeen != null && now - lastSeen < DEBOUNCE_MS) return
            recentUrls[url] = now
        }

        serviceScope.launch {
            val result = predictor.predict(url)

            // Always log to Room DB
            val record = ScanRecord(
                url = url,
                verdict = result.verdict.name,
                confidence = result.confidence,
                primaryReason = result.primaryReason,
                allReasons = com.google.gson.Gson().toJson(result.allReasons),
                geminiExplanation = result.geminiExplanation,
                cnnScore = result.cnnScore,
                bertScore = result.bertScore,
                anomalyScore = result.anomalyMse,
                domainAgeDays = result.domainAgeDays,
                layer = result.layer,
            )
            db.scanDao().insert(record)

            // Launch popup for non-SAFE verdicts
            when (result.verdict) {
                Verdict.SAFE -> { /* No popup — user uninterrupted */ }
                Verdict.NO_INTERNET -> {
                    val intent = Intent(this@URLInterceptService, NoInternetPopupActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        putExtra("url", url)
                    }
                    startActivity(intent)
                }
                else -> {
                    val intent = Intent(this@URLInterceptService, VerdictPopupActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        putExtra("url", url)
                        putExtra("verdict", result.verdict.name)
                        putExtra("confidence", result.confidence)
                        putExtra("primary_reason", result.primaryReason)
                        putExtra("gemini_explanation", result.geminiExplanation)
                        putExtra("cnn_score", result.cnnScore)
                        putExtra("bert_score", result.bertScore)
                        putExtra("anomaly_mse", result.anomalyMse)
                        putExtra("domain_age_days", result.domainAgeDays)
                        putExtra("layer", result.layer)
                        putExtra("matched_brand", result.matchedBrand)
                    }
                    startActivity(intent)
                }
            }
        }
    }
}
