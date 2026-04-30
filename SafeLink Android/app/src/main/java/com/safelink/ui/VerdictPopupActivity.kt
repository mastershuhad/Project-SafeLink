package com.safelink.ui

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

        val url               = intent.getStringExtra("url") ?: ""
        val verdictName       = intent.getStringExtra("verdict") ?: "WARNING"
        val confidence        = intent.getFloatExtra("confidence", 0.5f)
        val primaryReason     = intent.getStringExtra("primary_reason") ?: ""
        val geminiExplanation = intent.getStringExtra("gemini_explanation") ?: ""

        val verdict = runCatching { Verdict.valueOf(verdictName) }.getOrElse { Verdict.WARNING }

        val header       = findViewById<View>(R.id.bannerStripe)
        val tvIcon       = findViewById<TextView>(R.id.tvVerdictIcon)
        val tvTitle      = findViewById<TextView>(R.id.tvVerdictTitle)
        val tvSubtitle   = findViewById<TextView>(R.id.tvVerdictSubtitle)
        val tvReason     = findViewById<TextView>(R.id.tvReason)
        val tvGemini     = findViewById<TextView>(R.id.tvGemini)
        val tvUrlPreview = findViewById<TextView>(R.id.tvUrlPreview)
        val tvConfidence = findViewById<TextView>(R.id.tvConfidence)
        val btnBlock     = findViewById<Button>(R.id.btnBlock)
        val btnOpen      = findViewById<Button>(R.id.btnOpenAnyway)

        tvUrlPreview.text = if (url.length > 60) url.take(30) + "…" + url.takeLast(20) else url
        tvConfidence.text = getString(R.string.confidence_format, (confidence * 100).toInt())
        tvReason.text     = primaryReason

        if (geminiExplanation.isNotBlank()) {
            tvGemini.visibility = View.VISIBLE
            tvGemini.text = geminiExplanation
        } else {
            tvGemini.visibility = View.GONE
        }

        when {
            verdict == Verdict.MALICIOUS && confidence > 0.85f -> {
                header.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvIcon.text     = "🚨"
                tvTitle.text    = getString(R.string.verdict_malicious_high)
                tvSubtitle.text = getString(R.string.verdict_malicious_high_sub)
                btnOpen.visibility = View.GONE
            }
            verdict == Verdict.MALICIOUS -> {
                header.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvIcon.text     = "⚠️"
                tvTitle.text    = getString(R.string.verdict_malicious_medium)
                tvSubtitle.text = getString(R.string.verdict_malicious_medium_sub)
                btnOpen.visibility = View.VISIBLE
            }
            verdict == Verdict.WARNING -> {
                header.setBackgroundResource(R.drawable.bg_verdict_header_warning)
                tvIcon.text     = "⚠️"
                tvTitle.text    = getString(R.string.verdict_warning)
                tvSubtitle.text = getString(R.string.verdict_warning_sub)
                btnOpen.visibility = View.VISIBLE
            }
            verdict == Verdict.BLOCKED -> {
                header.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvIcon.text     = "🚫"
                tvTitle.text    = getString(R.string.verdict_blocked)
                tvSubtitle.text = getString(R.string.verdict_blocked_sub)
                btnOpen.visibility = View.GONE
            }
            else -> {
                header.setBackgroundResource(R.drawable.bg_verdict_header_warning)
                tvIcon.text     = "⚠️"
                tvTitle.text    = getString(R.string.verdict_warning)
                tvSubtitle.text = getString(R.string.verdict_warning_sub)
                btnOpen.visibility = View.VISIBLE
            }
        }

        btnBlock.setOnClickListener { finish() }
        btnOpen.setOnClickListener {
            BrowserUtils.openInSavedBrowser(this, url)
            finish()
        }
    }
}
