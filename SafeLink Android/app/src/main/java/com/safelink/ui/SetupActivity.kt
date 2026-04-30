package com.safelink.ui

import android.app.role.RoleManager
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.safelink.R

/**
 * Two-step mandatory onboarding:
 *   Step 1 — Set SafeLink as the default browser (via RoleManager / system settings)
 *   Step 2 — Choose the real browser SafeLink opens safe links in
 *
 * The user cannot skip either step. MainActivity redirects here if setup is incomplete.
 */
class SetupActivity : AppCompatActivity() {

    private companion object {
        const val RC_BROWSER_ROLE = 1001
    }

    private lateinit var tvStepIndicator: TextView
    private lateinit var containerStep1: View
    private lateinit var containerStep2: View
    private lateinit var browserButtonContainer: LinearLayout
    private lateinit var tvNoBrowsers: TextView

    private var currentStep = 1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)

        tvStepIndicator = findViewById(R.id.tvStepIndicator)
        containerStep1 = findViewById(R.id.containerStep1)
        containerStep2 = findViewById(R.id.containerStep2)
        browserButtonContainer = findViewById(R.id.browserButtonContainer)
        tvNoBrowsers = findViewById(R.id.tvNoBrowsers)

        findViewById<View>(R.id.btnSetDefaultBrowser).setOnClickListener {
            requestDefaultBrowser()
        }

        // If SafeLink is already default (e.g. reinstall), skip straight to Step 2
        if (BrowserUtils.isDefaultBrowser(this)) {
            showStep2()
        } else {
            showStep1()
        }
    }

    override fun onResume() {
        super.onResume()
        // Advance to Step 2 once the user sets SafeLink as default
        if (currentStep == 1 && BrowserUtils.isDefaultBrowser(this)) {
            showStep2()
        }
    }

    // ── Step 1 ────────────────────────────────────────────────────

    private fun requestDefaultBrowser() {
        val rm = getSystemService(RoleManager::class.java)
        if (rm.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
            @Suppress("DEPRECATION")
            startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_BROWSER), RC_BROWSER_ROLE)
        } else {
            startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
        }
    }

    private fun showStep1() {
        currentStep = 1
        tvStepIndicator.text = getString(R.string.setup_step_indicator, 1)
        containerStep1.visibility = View.VISIBLE
        containerStep2.visibility = View.GONE
    }

    // ── Step 2 ────────────────────────────────────────────────────

    private fun showStep2() {
        currentStep = 2
        tvStepIndicator.text = getString(R.string.setup_step_indicator, 2)
        containerStep1.visibility = View.GONE
        containerStep2.visibility = View.VISIBLE

        val browsers = BrowserUtils.getInstalledBrowsers(this)
        browserButtonContainer.removeAllViews()

        if (browsers.isEmpty()) {
            tvNoBrowsers.visibility = View.VISIBLE
            return
        }

        tvNoBrowsers.visibility = View.GONE
        val margin8dp = (8 * resources.displayMetrics.density).toInt()

        browsers.forEach { browser ->
            val btn = Button(this).apply {
                text = browser.label
                setOnClickListener {
                    BrowserUtils.saveBrowserPackage(this@SetupActivity, browser.packageName)
                    goToMain()
                }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).also { it.topMargin = margin8dp }
            browserButtonContainer.addView(btn, lp)
        }
    }

    private fun goToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
