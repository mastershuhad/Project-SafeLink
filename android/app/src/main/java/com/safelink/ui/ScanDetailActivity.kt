package com.safelink.ui

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.safelink.R
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScanDetailActivity : AppCompatActivity() {

    private val dateFormat = SimpleDateFormat("dd MMM yyyy HH:mm:ss", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_detail)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = getString(R.string.scan_detail_title)

        val scanId = intent.getLongExtra("scan_id", -1L)
        if (scanId == -1L) { finish(); return }

        lifecycleScope.launch {
            val record = withContext(Dispatchers.IO) {
                SafeLinkDatabase.getInstance(this@ScanDetailActivity).scanDao().getById(scanId)
            }
            if (record != null) bindRecord(record) else finish()
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun bindRecord(r: ScanRecord) {
        tv(R.id.tvDetailUrl).text = r.url
        tv(R.id.tvDetailVerdict).text = r.verdict
        tv(R.id.tvDetailTimestamp).text = dateFormat.format(Date(r.timestamp))
        tv(R.id.tvDetailConfidence).text = "${(r.confidence * 100).toInt()}%"
        tv(R.id.tvDetailLayer).text = r.layer
        tv(R.id.tvDetailReason).text = r.primaryReason
        tv(R.id.tvDetailCnnScore).text = String.format("%.3f", r.cnnScore)
        tv(R.id.tvDetailBertScore).text = String.format("%.3f", r.bertScore)
        tv(R.id.tvDetailAnomalyMse).text = String.format("%.5f", r.anomalyScore)
        tv(R.id.tvDetailDomainAge).text =
            if (r.domainAgeDays < 0) getString(R.string.unknown)
            else "${r.domainAgeDays.toInt()} days"

        if (r.geminiExplanation.isNotBlank()) {
            tv(R.id.tvDetailGemini).text = r.geminiExplanation
            tv(R.id.tvDetailGemini).visibility = View.VISIBLE
            findViewById<View>(R.id.labelGemini).visibility = View.VISIBLE
        }

        // Verdict color
        val color = when (r.verdict) {
            "SAFE"      -> getColor(R.color.safe_green)
            "WARNING"   -> getColor(R.color.warning_orange)
            "MALICIOUS" -> getColor(R.color.danger_red)
            "BLOCKED"   -> getColor(R.color.danger_red)
            else        -> getColor(R.color.no_internet_blue)
        }
        tv(R.id.tvDetailVerdict).setTextColor(color)
    }

    private fun tv(id: Int): TextView = findViewById(id)
}
