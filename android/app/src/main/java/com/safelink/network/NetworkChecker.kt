package com.safelink.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

class NetworkChecker(private val context: Context) {

    private val cm = context.getSystemService(ConnectivityManager::class.java)

    /**
     * Returns true only when internet is available AND validated (rejects captive portals).
     */
    fun isConnected(): Boolean {
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }
}
