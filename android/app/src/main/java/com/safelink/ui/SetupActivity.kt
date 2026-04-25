package com.safelink.ui

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.safelink.R

class SetupActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)

        findViewById<View>(R.id.btnEnableAccessibility).setOnClickListener {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
    }

    override fun onResume() {
        super.onResume()
        // Auto-proceed when user has enabled the accessibility service
        if (isAccessibilityServiceEnabled()) {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val serviceId = "$packageName/.service.URLInterceptService"
        val enabled = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        return enabled.split(':').any { it.equals(serviceId, ignoreCase = true) }
    }
}
