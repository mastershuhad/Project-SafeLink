package com.safelink.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.safelink.R
import com.safelink.data.SafeLinkDatabase
import com.safelink.data.ScanRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScanHistoryActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var tvEmpty: TextView
    private lateinit var etSearch: EditText
    private val adapter = ScanHistoryAdapter { record ->
        val intent = Intent(this, ScanDetailActivity::class.java)
        intent.putExtra("scan_id", record.id)
        startActivity(intent)
    }

    private val db by lazy { SafeLinkDatabase.getInstance(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_history)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = getString(R.string.scan_history_title)

        recyclerView = findViewById(R.id.recyclerView)
        tvEmpty = findViewById(R.id.tvEmpty)
        etSearch = findViewById(R.id.etSearch)

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        etSearch.addTextChangedListener { loadRecords(it?.toString()?.trim() ?: "") }

        findViewById<Button>(R.id.btnClearHistory).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.clear_history_title)
                .setMessage(R.string.clear_history_message)
                .setPositiveButton(R.string.clear) { _, _ -> clearHistory() }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }

        loadRecords()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun loadRecords(query: String = "") {
        lifecycleScope.launch {
            val records = withContext(Dispatchers.IO) {
                if (query.isEmpty()) db.scanDao().getAll()
                else db.scanDao().search(query)
            }
            adapter.submitList(records)
            tvEmpty.visibility = if (records.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun clearHistory() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) { db.scanDao().clearAll() }
            adapter.submitList(emptyList())
            tvEmpty.visibility = View.VISIBLE
        }
    }
}
