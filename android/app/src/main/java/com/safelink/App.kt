package com.safelink

import android.app.Application
import com.safelink.knowledge.KnowledgeHubStore
import com.safelink.knowledge.KnowledgeHubUpdater
import com.safelink.ml.AutoencoderDetector
import com.safelink.ml.FeatureScaler
import com.safelink.ml.SafeLinkClassifier
import com.safelink.ml.URLBertClassifier
import com.safelink.network.BlocklistLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class App : Application() {

    companion object {
        lateinit var instance: App
            private set

        // Loaded at startup, kept in RAM while protection is enabled
        lateinit var blocklist: HashSet<String>
        lateinit var whitelist: HashSet<String>
        lateinit var knowledgeHub: KnowledgeHubStore
        lateinit var featureScaler: FeatureScaler
        lateinit var classifier: SafeLinkClassifier
        lateinit var bertClassifier: URLBertClassifier
        lateinit var autoencoderDetector: AutoencoderDetector

        @Volatile
        var modelsReady = false

        @Volatile
        var protectionEnabled = true
    }

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Restore protection toggle preference
        val prefs = getSharedPreferences("safelink_prefs", MODE_PRIVATE)
        protectionEnabled = prefs.getBoolean("protection_enabled", true)

        // Load all models and assets on IO thread — keeps UI snappy
        appScope.launch {
            try {
                blocklist = BlocklistLoader.loadBlocklist(applicationContext)
                whitelist = BlocklistLoader.loadWhitelist(applicationContext)

                knowledgeHub = KnowledgeHubStore(applicationContext)
                knowledgeHub.load()

                featureScaler = FeatureScaler(applicationContext)
                classifier = SafeLinkClassifier(applicationContext)
                bertClassifier = URLBertClassifier(applicationContext)
                autoencoderDetector = AutoencoderDetector(applicationContext)

                modelsReady = true

                // Check for Knowledge Hub updates once per day (background)
                KnowledgeHubUpdater(applicationContext, knowledgeHub).checkAndUpdate()
            } catch (e: Exception) {
                // Log startup failure — app degrades gracefully (no ML, blocklist-only)
                android.util.Log.e("SafeLink", "Model load failed: ${e.message}", e)
            }
        }
    }
}
