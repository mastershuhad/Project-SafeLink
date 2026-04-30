package com.safelink.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_records")
data class ScanRecord(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val url: String,
    val verdict: String,           // SAFE / WARNING / MALICIOUS / BLOCKED / NO_INTERNET
    val confidence: Float,
    val timestamp: Long = System.currentTimeMillis(),
    val primaryReason: String,
    val allReasons: String,        // JSON array of strings
    val geminiExplanation: String,
    val cnnScore: Float,
    val bertScore: Float,
    val anomalyScore: Float,
    val domainAgeDays: Float,
    val layer: String,             // L0-* / L1-* / L2-* / L3-*
)
