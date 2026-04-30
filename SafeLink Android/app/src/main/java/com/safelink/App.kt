package com.safelink

import android.app.Application
import com.safelink.knowledge.KnowledgeHubStore
import com.safelink.knowledge.KnowledgeHubUpdater
import com.safelink.ml.AutoencoderDetector
import com.safelink.ml.FeatureScaler
import com.safelink.ml.SafeLinkClassifier
import com.safelink.ml.URLBertClassifier
import com.safelink.network.BlocklistLoader
import com.safelink.network.DynamicWhitelist
import com.safelink.network.GeminiClient
import com.safelink.network.GoogleSafeBrowsingClient
import com.safelink.network.RDAPClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class App : Application() {

    companion object {
        lateinit var instance: App
            private set

        // Always available (loaded with fallback on failure)
        lateinit var blocklist: HashSet<String>
        lateinit var whitelist: HashSet<String>
        lateinit var knowledgeHub: KnowledgeHubStore

        // Critical — modelsReady stays false if either fails
        lateinit var featureScaler: FeatureScaler
        lateinit var classifier: SafeLinkClassifier

        // Network clients (shared instances)
        lateinit var rdapClient: RDAPClient
        lateinit var gsbClient: GoogleSafeBrowsingClient
        lateinit var geminiClient: GeminiClient
        lateinit var dynamicWhitelist: DynamicWhitelist

        // Optional — null means that model failed to load; pipeline skips it
        @Volatile var bertClassifier: URLBertClassifier? = null
        @Volatile var autoencoderDetector: AutoencoderDetector? = null

        @Volatile var modelsReady = false
        @Volatile var modelsFailed = false
        @Volatile var protectionEnabled = true
    }

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        instance = this

        val prefs = getSharedPreferences("safelink_prefs", MODE_PRIVATE)
        protectionEnabled = prefs.getBoolean("protection_enabled", true)

        // Initialize shared clients
        rdapClient = RDAPClient()
        gsbClient = GoogleSafeBrowsingClient()
        geminiClient = GeminiClient()
        dynamicWhitelist = DynamicWhitelist(this)

        appScope.launch { loadModels() }
    }

    private fun loadModels() {
        // ── Always-needed assets (never fail hard) ────────────────
        try {
            blocklist = BlocklistLoader.loadBlocklist(applicationContext)
            whitelist = BlocklistLoader.loadWhitelist(applicationContext)
            android.util.Log.d("SafeLink/Init", "Blocklist: ${blocklist.size} entries")
        } catch (t: Throwable) {
            blocklist = HashSet(); whitelist = HashSet()
            android.util.Log.e("SafeLink/Init", "Blocklist load failed: ${t.message}", t)
        }

        try {
            knowledgeHub = KnowledgeHubStore(applicationContext).also { it.load() }
            android.util.Log.d("SafeLink/Init", "KnowledgeHub loaded")
        } catch (t: Throwable) {
            knowledgeHub = KnowledgeHubStore(applicationContext)
            android.util.Log.e("SafeLink/Init", "KnowledgeHub load failed: ${t.message}", t)
        }

        // ── Critical models (CNN + scaler) ────────────────────────
        try {
            android.util.Log.d("SafeLink/Init", "Loading FeatureScaler…")
            featureScaler = FeatureScaler(applicationContext)
            android.util.Log.d("SafeLink/Init", "FeatureScaler ✓")
        } catch (t: Throwable) {
            modelsFailed = true
            android.util.Log.e("SafeLink/Init", "CRITICAL — FeatureScaler failed: ${t.javaClass.simpleName}: ${t.message}", t)
            return
        }

        try {
            android.util.Log.d("SafeLink/Init", "Loading SafeLinkClassifier (TFLite)…")
            classifier = SafeLinkClassifier(applicationContext)
            android.util.Log.d("SafeLink/Init", "SafeLinkClassifier ✓")
        } catch (t: Throwable) {
            modelsFailed = true
            android.util.Log.e("SafeLink/Init", "CRITICAL — SafeLinkClassifier failed: ${t.javaClass.simpleName}: ${t.message}", t)
            return
        }

        // ── Optional models (URLBert + Autoencoder) ───────────────
        try {
            android.util.Log.d("SafeLink/Init", "Loading URLBertClassifier (ONNX)…")
            bertClassifier = URLBertClassifier(applicationContext)
            android.util.Log.d("SafeLink/Init", "URLBertClassifier ✓")
        } catch (t: Throwable) {
            android.util.Log.e("SafeLink/Init", "OPTIONAL — URLBert failed (CNN-only mode): ${t.javaClass.simpleName}: ${t.message}", t)
        }

        try {
            android.util.Log.d("SafeLink/Init", "Loading AutoencoderDetector (TFLite)…")
            autoencoderDetector = AutoencoderDetector(applicationContext)
            android.util.Log.d("SafeLink/Init", "AutoencoderDetector ✓")
        } catch (t: Throwable) {
            android.util.Log.e("SafeLink/Init", "OPTIONAL — Autoencoder failed (skipping anomaly): ${t.javaClass.simpleName}: ${t.message}", t)
        }

        modelsReady = true
        android.util.Log.d("SafeLink/Init",
            "Models ready ✓  bert=${bertClassifier != null}  ae=${autoencoderDetector != null}")

        try {
            KnowledgeHubUpdater(applicationContext, knowledgeHub).checkAndUpdate()
        } catch (t: Throwable) {
            android.util.Log.w("SafeLink/Init", "KnowledgeHub update skipped: ${t.message}")
        }
    }
}
