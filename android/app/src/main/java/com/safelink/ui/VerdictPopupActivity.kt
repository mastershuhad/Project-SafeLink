package com.safelink.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.safelink.R
import com.safelink.ml.Verdict

class VerdictPopupActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_verdict_popup)

        val url = intent.getStringExtra("url") ?: ""
        val verdictName = intent.getStringExtra("verdict") ?: "WARNING"
        val confidence = intent.getFloatExtra("confidence", 0.5f)
        val primaryReason = intent.getStringExtra("primary_reason") ?: ""
        val geminiExplanation = intent.getStringExtra("gemini_explanation") ?: ""
        val cnnScore = intent.getFloatExtra("cnn_score", 0f)
        val bertScore = intent.getFloatExtra("bert_score", 0f)
        val anomalyMse = intent.getFloatExtra("anomaly_mse", 0f)
        val domainAgeDays = intent.getFloatExtra("domain_age_days", -1f)
        val layer = intent.getStringExtra("layer") ?: ""
        val matchedBrand = intent.getStringExtra("matched_brand")

        val verdict = runCatching { Verdict.valueOf(verdictName) }.getOrElse { Verdict.WARNING }

        val banner = findViewById<View>(R.id.bannerStripe)
        val tvTitle = findViewById<TextView>(R.id.tvVerdictTitle)
        val tvSubtitle = findViewById<TextView>(R.id.tvVerdictSubtitle)
        val tvReason = findViewById<TextView>(R.id.tvReason)
        val tvGemini = findViewById<TextView>(R.id.tvGemini)
        val tvUrlPreview = findViewById<TextView>(R.id.tvUrlPreview)
        val tvConfidence = findViewById<TextView>(R.id.tvConfidence)
        val btnBlock = findViewById<Button>(R.id.btnBlock)
        val btnOpenAnyway = findViewById<Button>(R.id.btnOpenAnyway)

        // URL preview — truncate middle if too long
        tvUrlPreview.text = if (url.length > 60) url.take(30) + "…" + url.takeLast(20) else url
        tvConfidence.text = getString(R.string.confidence_format, (confidence * 100).toInt())

        // Reason
        tvReason.text = primaryReason

        // Gemini explanation (WARNING only, hidden when empty)
        if (geminiExplanation.isNotBlank()) {
            tvGemini.visibility = View.VISIBLE
            tvGemini.text = geminiExplanation
        } else {
            tvGemini.visibility = View.GONE
        }

        // Verdict-specific styling
        when {
            verdict == Verdict.MALICIOUS && confidence > 0.85f -> {
                banner.setBackgroundColor(getColor(R.color.danger_red))
                tvTitle.text = getString(R.string.verdict_malicious_high)
                tvSubtitle.text = getString(R.string.verdict_malicious_high_sub)
                btnOpenAnyway.visibility = View.GONE  // No override for high-confidence malicious
            }
            verdict == Verdict.MALICIOUS -> {
                banner.setBackgroundColor(getColor(R.color.danger_red_soft))
                tvTitle.text = getString(R.string.verdict_malicious_medium)
                tvSubtitle.text = getString(R.string.verdict_malicious_medium_sub)
                btnOpenAnyway.visibility = View.VISIBLE
            }
            verdict == Verdict.WARNING -> {
                banner.setBackgroundColor(getColor(R.color.warning_orange))
                tvTitle.text = getString(R.string.verdict_warning)
                tvSubtitle.text = getString(R.string.verdict_warning_sub)
                btnOpenAnyway.visibility = View.VISIBLE
            }
            verdict == Verdict.BLOCKED -> {
                banner.setBackgroundColor(getColor(R.color.danger_red))
                tvTitle.text = getString(R.string.verdict_blocked)
                tvSubtitle.text = getString(R.string.verdict_blocked_sub)
                btnOpenAnyway.visibility = View.GONE
            }
            else -> {
                banner.setBackgroundColor(getColor(R.color.warning_orange))
                tvTitle.text = getString(R.string.verdict_warning)
                tvSubtitle.text = getString(R.string.verdict_warning_sub)
            }
        }

        btnBlock.setOnClickListener { finish() }

        btnOpenAnyway.setOnClickListener {
            // User overrides — open URL in browser
            try {
                val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(browserIntent)
            } catch (e: Exception) {
                // ignore
            }
            finish()
        }
    }
}
