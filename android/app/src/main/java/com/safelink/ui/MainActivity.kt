package com.safelink.ui

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.switchmaterial.SwitchMaterial
import com.safelink.App
import com.safelink.R
import com.safelink.data.SafeLinkDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var switchProtection: SwitchMaterial
    private lateinit var bannerOffline: View
    private lateinit var tvStatus: TextView
    private lateinit var tvScanCount: TextView

    private val connectivityManager by lazy {
        getSystemService(ConnectivityManager::class.java)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            runOnUiThread { updateOfflineBanner(online = true) }
        }
        override fun onLost(network: Network) {
            runOnUiThread { updateOfflineBanner(online = false) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Redirect to setup if accessibility service not enabled
        if (!isAccessibilityServiceEnabled()) {
            startActivity(Intent(this, SetupActivity::class.java))
            finish()
            return
        }

        setContentView(R.layout.activity_main)

        switchProtection = findViewById(R.id.switchProtection)
        bannerOffline = findViewById(R.id.bannerOffline)
        tvStatus = findViewById(R.id.tvStatus)
        tvScanCount = findViewById(R.id.tvScanCount)

        // Initialise toggle from current state
        switchProtection.isChecked = App.protectionEnabled
        updateStatusText()

        switchProtection.setOnCheckedChangeListener { _, isChecked ->
            App.protectionEnabled = isChecked
            getSharedPreferences("safelink_prefs", MODE_PRIVATE)
                .edit().putBoolean("protection_enabled", isChecked).apply()
            updateStatusText()
        }

        findViewById<View>(R.id.btnScanHistory).setOnClickListener {
            startActivity(Intent(this, ScanHistoryActivity::class.java))
        }

        loadScanCount()

        // Register network callback for offline banner
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(req, networkCallback)

        // Initial offline state
        updateOfflineBanner(isOnline())
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
    }

    override fun onResume() {
        super.onResume()
        loadScanCount()
    }

    private fun loadScanCount() {
        lifecycleScope.launch {
            val count = withContext(Dispatchers.IO) {
                SafeLinkDatabase.getInstance(this@MainActivity).scanDao().count()
            }
            tvScanCount.text = if (count == 0) "No links scanned yet" else "$count links scanned"
        }
    }

    private fun updateStatusText() {
        tvStatus.text = if (App.protectionEnabled) {
            getString(R.string.status_protection_on)
        } else {
            getString(R.string.status_protection_off)
        }
    }

    private fun updateOfflineBanner(online: Boolean) {
        bannerOffline.visibility = if (online) View.GONE else View.VISIBLE
    }

    private fun isOnline(): Boolean {
        val network = connectivityManager.activeNetwork ?: return false
        val caps = connectivityManager.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val serviceId = "$packageName/.service.URLInterceptService"
        val enabled = android.provider.Settings.Secure.getString(
            contentResolver,
            android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        return enabled.split(':').any { it.equals(serviceId, ignoreCase = true) }
    }
}
