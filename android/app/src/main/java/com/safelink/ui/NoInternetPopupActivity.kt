package com.safelink.ui

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.safelink.R

class NoInternetPopupActivity : AppCompatActivity() {

    private val connectivityManager by lazy {
        getSystemService(ConnectivityManager::class.java)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val caps = connectivityManager.getNetworkCapabilities(network) ?: return
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                // Internet restored — auto-retry the scan
                runOnUiThread { retryAndDismiss() }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_no_internet_popup)

        val url = intent.getStringExtra("url") ?: ""
        val tvUrl = findViewById<TextView>(R.id.tvUrlPreview)
        tvUrl.text = if (url.length > 60) url.take(30) + "…" + url.takeLast(20) else url

        findViewById<Button>(R.id.btnOk).setOnClickListener { finish() }

        // Register network callback to auto-dismiss when internet returns
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()
        connectivityManager.registerNetworkCallback(req, networkCallback)
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
    }

    private fun retryAndDismiss() {
        // Dismiss popup — URLInterceptService will re-detect the URL naturally
        finish()
    }
}
