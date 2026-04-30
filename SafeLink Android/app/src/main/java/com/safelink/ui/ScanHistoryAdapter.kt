package com.safelink.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.safelink.R
import com.safelink.data.ScanRecord
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScanHistoryAdapter(
    private val onItemClick: (ScanRecord) -> Unit,
) : ListAdapter<ScanRecord, ScanHistoryAdapter.ViewHolder>(DIFF_CALLBACK) {

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ScanRecord>() {
            override fun areItemsTheSame(a: ScanRecord, b: ScanRecord) = a.id == b.id
            override fun areContentsTheSame(a: ScanRecord, b: ScanRecord) = a == b
        }
        private val DATE_FORMAT = SimpleDateFormat("dd MMM yyyy HH:mm", Locale.getDefault())
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val dotVerdict: View = itemView.findViewById(R.id.dotVerdict)
        val tvUrl: TextView = itemView.findViewById(R.id.tvUrl)
        val tvReason: TextView = itemView.findViewById(R.id.tvReason)
        val tvTimestamp: TextView = itemView.findViewById(R.id.tvTimestamp)
        val tvVerdictBadge: TextView = itemView.findViewById(R.id.tvVerdictBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_scan_record, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val record = getItem(position)
        val ctx = holder.itemView.context

        // URL — ellipsize middle
        holder.tvUrl.text = if (record.url.length > 55) {
            record.url.take(28) + "…" + record.url.takeLast(18)
        } else {
            record.url
        }

        holder.tvReason.text = record.primaryReason
        holder.tvTimestamp.text = DATE_FORMAT.format(Date(record.timestamp))
        holder.tvVerdictBadge.text = record.verdict

        // Color-coded verdict dot
        val dotColor = when (record.verdict) {
            "SAFE"       -> ctx.getColor(R.color.safe_green)
            "WARNING"    -> ctx.getColor(R.color.warning_orange)
            "MALICIOUS"  -> ctx.getColor(R.color.danger_red)
            "BLOCKED"    -> ctx.getColor(R.color.danger_red)
            else         -> ctx.getColor(R.color.no_internet_blue)
        }
        holder.dotVerdict.background.setTint(dotColor)
        holder.tvVerdictBadge.setTextColor(dotColor)

        holder.itemView.setOnClickListener { onItemClick(record) }
    }
}
