package com.safelink.ui

import android.app.AlertDialog
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
    private lateinit var tvBrowserLabel: TextView
    private lateinit var bannerNotDefault: View

    private val connectivityManager by lazy {
        getSystemService(ConnectivityManager::class.java)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = runOnUiThread { updateOfflineBanner(true) }
        override fun onLost(network: Network) = runOnUiThread { updateOfflineBanner(false) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block entry until the user has completed both setup steps
        if (!isSetupComplete()) {
            startActivity(Intent(this, SetupActivity::class.java))
            finish()
            return
        }

        setContentView(R.layout.activity_main)

        switchProtection = findViewById(R.id.switchProtection)
        bannerOffline = findViewById(R.id.bannerOffline)
        tvStatus = findViewById(R.id.tvStatus)
        tvScanCount = findViewById(R.id.tvScanCount)
        tvBrowserLabel = findViewById(R.id.tvBrowserLabel)
        bannerNotDefault = findViewById(R.id.bannerNotDefault)

        switchProtection.isChecked = App.protectionEnabled
        updateStatusText()

        switchProtection.setOnCheckedChangeListener { _, isChecked ->
            App.protectionEnabled = isChecked
            getSharedPreferences("safelink_prefs", MODE_PRIVATE)
                .edit().putBoolean("protection_enabled", isChecked).apply()
            updateStatusText()
        }

        findViewById<View>(R.id.btnManualTest).setOnClickListener {
            startActivity(Intent(this, ManualTestActivity::class.java))
        }

        findViewById<View>(R.id.btnScanHistory).setOnClickListener {
            startActivity(Intent(this, ScanHistoryActivity::class.java))
        }

        findViewById<View>(R.id.btnChangeBrowser).setOnClickListener {
            showBrowserPicker()
        }

        bannerNotDefault.setOnClickListener {
            startActivity(Intent(this, SetupActivity::class.java))
        }

        loadScanCount()

        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
        connectivityManager.registerNetworkCallback(req, networkCallback)
        updateOfflineBanner(isOnline())
    }

    override fun onResume() {
        super.onResume()
        loadScanCount()
        updateBrowserLabel()
        bannerNotDefault.visibility =
            if (BrowserUtils.isDefaultBrowser(this)) View.GONE else View.VISIBLE
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
    }

    private fun updateBrowserLabel() {
        val label = BrowserUtils.getSavedBrowserLabel(this) ?: getString(R.string.browser_not_selected)
        tvBrowserLabel.text = getString(R.string.real_browser_label, label)
    }

    private fun showBrowserPicker() {
        val browsers = BrowserUtils.getInstalledBrowsers(this)
        if (browsers.isEmpty()) return
        val labels = browsers.map { it.label }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle(R.string.browser_picker_title)
            .setItems(labels) { _, i ->
                BrowserUtils.saveBrowserPackage(this, browsers[i].packageName)
                updateBrowserLabel()
            }
            .show()
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
        tvStatus.text = if (App.protectionEnabled)
            getString(R.string.status_protection_on)
        else
            getString(R.string.status_protection_off)
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

    /**
     * Setup is complete when the user has:
     *   1. Set SafeLink as the default browser
     *   2. Chosen a real browser for SafeLink to open links in
     */
    private fun isSetupComplete(): Boolean =
        BrowserUtils.isDefaultBrowser(this) && BrowserUtils.getSavedBrowserPackage(this) != null
}
