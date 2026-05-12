package com.safelink.ui

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.safelink.App
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import com.safelink.ml.Verdict
import com.safelink.network.NetworkChecker
import com.safelink.service.SafeLinkPredictor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class InterceptActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val url = intent?.data?.toString()
        if (url == null) { finish(); return }

        if (!App.protectionEnabled) {
            BrowserUtils.openInSavedBrowser(this, url)
            finish()
            return
        }

        lifecycleScope.launch {
            val predictor = SafeLinkPredictor(
                networkChecker = NetworkChecker(this@InterceptActivity),
                geminiClient = App.geminiClient,
                dynamicWhitelist = App.dynamicWhitelist,
            )

            val result = withContext(Dispatchers.IO) { predictor.predict(url) }

            withContext(Dispatchers.IO) {
                SafeLinkDatabase.getInstance(this@InterceptActivity).scanDao().insert(
                    ScanRecord(
                        url = url,
                        verdict = result.verdict.name,
                        confidence = result.confidence,
                        primaryReason = result.primaryReason,
                        allReasons = Gson().toJson(result.allReasons),
                        geminiExplanation = result.geminiExplanation,
                        cnnScore = result.cnnScore,
                        bertScore = result.bertScore,
                        anomalyScore = result.anomalyMse,
                        domainAgeDays = result.domainAgeDays,
                        layer = result.layer,
                    )
                )
            }

            when (result.verdict) {
                Verdict.SAFE -> BrowserUtils.openInSavedBrowser(this@InterceptActivity, url)
                Verdict.NO_INTERNET -> startActivity(
                    Intent(this@InterceptActivity, NoInternetPopupActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        putExtra("url", url)
                    }
                )
                else -> startActivity(
                    Intent(this@InterceptActivity, VerdictComposeActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
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
                )
            }
            finish()
        }
    }
}
