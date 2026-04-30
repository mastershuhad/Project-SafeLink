package com.safelink.ui

import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.safelink.App
import com.safelink.R
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import com.safelink.ml.Verdict
import com.safelink.network.NetworkChecker
import com.safelink.service.PredictionResult
import com.safelink.service.SafeLinkPredictor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ManualTestActivity : AppCompatActivity() {

    private lateinit var etUrl: EditText
    private lateinit var btnCheck: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var cardResult: View
    private lateinit var bannerStripe: View
    private lateinit var tvVerdictIcon: TextView
    private lateinit var tvVerdictTitle: TextView
    private lateinit var tvVerdictSubtitle: TextView
    private lateinit var tvUrlPreview: TextView
    private lateinit var tvReason: TextView
    private lateinit var tvGemini: TextView
    private lateinit var tvConfidence: TextView
    private lateinit var tvDomainAge: TextView
    private lateinit var tvLayer: TextView
    private lateinit var tvScores: TextView
    private lateinit var btnOpenLink: Button
    private lateinit var btnCheckAnother: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_manual_test)

        supportActionBar?.apply {
            title = getString(R.string.manual_test_title)
            setDisplayHomeAsUpEnabled(true)
        }

        etUrl           = findViewById(R.id.etUrl)
        btnCheck        = findViewById(R.id.btnCheck)
        progressBar     = findViewById(R.id.progressBar)
        cardResult      = findViewById(R.id.cardResult)
        bannerStripe    = findViewById(R.id.bannerStripe)
        tvVerdictIcon   = findViewById(R.id.tvVerdictIcon)
        tvVerdictTitle  = findViewById(R.id.tvVerdictTitle)
        tvVerdictSubtitle = findViewById(R.id.tvVerdictSubtitle)
        tvUrlPreview    = findViewById(R.id.tvUrlPreview)
        tvReason        = findViewById(R.id.tvReason)
        tvGemini        = findViewById(R.id.tvGemini)
        tvConfidence    = findViewById(R.id.tvConfidence)
        tvDomainAge     = findViewById(R.id.tvDomainAge)
        tvLayer         = findViewById(R.id.tvLayer)
        tvScores        = findViewById(R.id.tvScores)
        btnOpenLink     = findViewById(R.id.btnOpenLink)
        btnCheckAnother = findViewById(R.id.btnCheckAnother)

        btnCheck.setOnClickListener { startScan() }

        etUrl.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEARCH) { startScan(); true } else false
        }

        btnCheckAnother.setOnClickListener { resetForm() }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    private fun startScan() {
        val raw = etUrl.text.toString().trim()
        if (raw.isBlank()) { etUrl.error = "Enter a URL"; return }

        val url = if (raw.startsWith("http://") || raw.startsWith("https://")) raw
                  else "https://$raw"

        hideKeyboard()
        cardResult.visibility  = View.GONE
        progressBar.visibility = View.VISIBLE
        btnCheck.isEnabled     = false

        lifecycleScope.launch {
            val predictor = SafeLinkPredictor(
                networkChecker   = NetworkChecker(this@ManualTestActivity),
                rdapClient       = App.rdapClient,
                gsbClient        = App.gsbClient,
                geminiClient     = App.geminiClient,
                dynamicWhitelist = App.dynamicWhitelist,
            )

            val result = withContext(Dispatchers.IO) { predictor.predict(url) }

            withContext(Dispatchers.IO) {
                SafeLinkDatabase.getInstance(this@ManualTestActivity).scanDao().insert(
                    ScanRecord(
                        url              = url,
                        verdict          = result.verdict.name,
                        confidence       = result.confidence,
                        primaryReason    = result.primaryReason,
                        allReasons       = Gson().toJson(result.allReasons),
                        geminiExplanation = result.geminiExplanation,
                        cnnScore         = result.cnnScore,
                        bertScore        = result.bertScore,
                        anomalyScore     = result.anomalyMse,
                        domainAgeDays    = result.domainAgeDays,
                        layer            = result.layer,
                    )
                )
            }

            progressBar.visibility = View.GONE
            btnCheck.isEnabled     = true
            showResult(url, result)
        }
    }

    private fun showResult(url: String, result: PredictionResult) {
        tvUrlPreview.text = if (url.length > 60) url.take(30) + "…" + url.takeLast(20) else url
        tvConfidence.text = getString(R.string.confidence_format, (result.confidence * 100).toInt())
        tvReason.text     = result.primaryReason
        tvLayer.text      = result.layer

        if (result.geminiExplanation.isNotBlank()) {
            tvGemini.visibility = View.VISIBLE
            tvGemini.text       = result.geminiExplanation
        } else {
            tvGemini.visibility = View.GONE
        }

        tvDomainAge.text = when {
            result.domainAgeDays < 0  -> "Domain age: unknown"
            result.domainAgeDays < 30  -> "Domain age: ${result.domainAgeDays.toInt()} days ⚠️ very new"
            result.domainAgeDays < 365 -> "Domain age: ${result.domainAgeDays.toInt()} days"
            else -> {
                val years = (result.domainAgeDays / 365).toInt()
                "Domain age: $years yr${if (years == 1) "" else "s"}"
            }
        }

        tvScores.text = "CNN %.2f  |  BERT %.2f  |  AE %.4f".format(
            result.cnnScore, result.bertScore, result.anomalyMse
        )

        when {
            result.verdict == Verdict.SAFE -> {
                bannerStripe.setBackgroundResource(R.drawable.bg_verdict_header_safe)
                tvVerdictIcon.text    = "✅"
                tvVerdictTitle.text   = getString(R.string.verdict_safe)
                tvVerdictSubtitle.text = getString(R.string.verdict_safe_sub)
                btnOpenLink.visibility = View.VISIBLE
            }
            result.verdict == Verdict.MALICIOUS && result.confidence > 0.85f -> {
                bannerStripe.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvVerdictIcon.text    = "🚨"
                tvVerdictTitle.text   = getString(R.string.verdict_malicious_high)
                tvVerdictSubtitle.text = getString(R.string.verdict_malicious_high_sub)
                btnOpenLink.visibility = View.GONE
            }
            result.verdict == Verdict.MALICIOUS -> {
                bannerStripe.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvVerdictIcon.text    = "⚠️"
                tvVerdictTitle.text   = getString(R.string.verdict_malicious_medium)
                tvVerdictSubtitle.text = getString(R.string.verdict_malicious_medium_sub)
                btnOpenLink.visibility = View.VISIBLE
            }
            result.verdict == Verdict.BLOCKED -> {
                bannerStripe.setBackgroundResource(R.drawable.bg_verdict_header_danger)
                tvVerdictIcon.text    = "🚫"
                tvVerdictTitle.text   = getString(R.string.verdict_blocked)
                tvVerdictSubtitle.text = getString(R.string.verdict_blocked_sub)
                btnOpenLink.visibility = View.GONE
            }
            else -> {
                bannerStripe.setBackgroundResource(R.drawable.bg_verdict_header_warning)
                tvVerdictIcon.text    = "⚠️"
                tvVerdictTitle.text   = getString(R.string.verdict_warning)
                tvVerdictSubtitle.text = getString(R.string.verdict_warning_sub)
                btnOpenLink.visibility = View.VISIBLE
            }
        }

        btnOpenLink.setOnClickListener {
            BrowserUtils.openInSavedBrowser(this, url)
        }

        cardResult.visibility = View.VISIBLE
    }

    private fun resetForm() {
        etUrl.text.clear()
        cardResult.visibility = View.GONE
        etUrl.requestFocus()
        showKeyboard()
    }

    private fun hideKeyboard() {
        val imm = getSystemService(InputMethodManager::class.java)
        imm.hideSoftInputFromWindow(etUrl.windowToken, 0)
    }

    private fun showKeyboard() {
        val imm = getSystemService(InputMethodManager::class.java)
        imm.showSoftInput(etUrl, InputMethodManager.SHOW_IMPLICIT)
    }
}
