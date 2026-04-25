package com.safelink.ml

import android.net.Uri
import java.net.IDN
import kotlin.math.ln

/**
 * Mirrors Python feature_extractor.py — computes all 35 URL features.
 * Feature index 35 (domain_age_days, 0-indexed) is initialized to -1.0f
 * and filled later by RDAPClient.
 */
object FeatureExtractor {

    private val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "club", "online", "site", "info", "biz", "tk", "ml",
        "ga", "cf", "gq", "click", "link", "download", "win", "loan", "work",
        "review", "stream", "gdn", "racing", "accountant", "science", "date",
        "faith", "party", "trade", "webcam", "cricket", "bid", "rocks",
    )

    private val TRUSTED_TLDS = setOf("gov", "edu", "mil", "ac")

    private val PHISHING_KEYWORDS = setOf(
        "login", "signin", "account", "update", "secure", "verify", "banking",
        "payment", "password", "credential", "confirm", "suspend", "unlock",
        "alert", "warning", "urgent", "limited", "expire", "reward", "prize",
        "winner", "free", "bonus", "offer", "click", "support", "help",
        "service", "customer", "billing", "invoice", "refund", "upgrade",
    )

    private val BRAND_KEYWORDS = setOf(
        "hnb", "sampath", "boc", "commercial", "dialog", "mobitel", "slt",
        "peoples", "bank", "lankabell",
        "paypal", "amazon", "google", "facebook", "apple", "microsoft",
        "netflix", "instagram", "whatsapp", "dhl", "ebay", "linkedin",
        "twitter", "youtube", "dropbox", "adobe", "office", "outlook",
    )

    private val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "tiny.cc",
    )

    private val TLD_IN_PATH_REGEX = Regex(
        """\.(com|net|org|gov|edu|bank|secure|login)\b""", RegexOption.IGNORE_CASE
    )

    private val DIGIT_RUN_REGEX = Regex("""\d+""")

    fun extract(url: String): FloatArray {
        val f = FloatArray(36) { 0f }
        f[35] = -1.0f  // domain_age_days placeholder

        val normalized = if ("://" !in url) "http://$url" else url
        val uri = runCatching { Uri.parse(normalized) }.getOrNull()

        val scheme = uri?.scheme ?: "http"
        val host = uri?.host?.lowercase() ?: ""
        val path = uri?.path ?: ""
        val query = uri?.query ?: ""

        // Normalize host — strip www.
        val domainNoWww = host.removePrefix("www.")
        val parts = domainNoWww.split('.')
        val tld = if (parts.size > 1) parts.last() else ""
        val sld = if (parts.size > 1) parts[parts.size - 2] else domainNoWww
        val subdomain = if (parts.size > 2) parts.dropLast(2).joinToString(".") else ""

        val isIp = isIpAddress(host)

        f[0]  = url.length.toFloat()                          // url_length
        f[1]  = host.length.toFloat()                         // domain_length
        f[2]  = path.length.toFloat()                         // path_length
        f[3]  = query.length.toFloat()                        // query_length
        f[4]  = url.count { it == '.' }.toFloat()             // num_dots
        f[5]  = url.count { it == '-' }.toFloat()             // num_hyphens
        f[6]  = url.count { it == '_' }.toFloat()             // num_underscores
        f[7]  = url.count { it == '/' }.toFloat()             // num_slashes
        f[8]  = url.count { it == '@' }.toFloat()             // num_at_signs
        f[9]  = url.count { it == '?' }.toFloat()             // num_question_marks
        f[10] = url.count { it == '=' }.toFloat()             // num_equals
        f[11] = url.count { it == '&' }.toFloat()             // num_ampersands
        f[12] = url.count { it == '%' }.toFloat()             // num_percent_signs
        f[13] = url.count { it.isDigit() }.toFloat()          // num_digits
        f[14] = if (url.isNotEmpty()) url.count { it.isDigit() }.toFloat() / url.length else 0f  // digit_ratio
        f[15] = entropy(url)                                  // url_entropy
        f[16] = entropy(host)                                 // domain_entropy
        f[17] = if (scheme == "https") 1f else 0f            // is_https
        f[18] = if (isIp) 1f else 0f                          // is_ip_address
        f[19] = (if (subdomain.isEmpty()) 0 else subdomain.split('.').size).toFloat() // num_subdomains
        f[20] = if (tld in SUSPICIOUS_TLDS) 1f else 0f       // has_suspicious_tld
        f[21] = if (tld in TRUSTED_TLDS) 1f else 0f          // has_trusted_tld

        // Tokenize the URL for keyword matching
        val words = url.lowercase()
            .replace('/', ' ')
            .replace('-', ' ')
            .replace('_', ' ')
            .replace('.', ' ')
            .split(Regex("\\W+"))
            .toSet()

        f[22] = (PHISHING_KEYWORDS intersect words).size.toFloat()  // phishing_keyword_count
        f[23] = (BRAND_KEYWORDS intersect words).size.toFloat()     // brand_keyword_count
        f[24] = if (URL_SHORTENERS.any { it in host }) 1f else 0f   // has_url_shortener

        f[25] = (uri?.queryParameterNames?.size ?: 0).toFloat()     // num_query_params
        f[26] = if (uri?.encodedAuthority?.contains(':') == true) 1f else 0f  // has_port_in_url
        f[27] = if ("//" in path) 1f else 0f                        // has_double_slash_in_path
        f[28] = subdomain.length.toFloat()                          // subdomain_length
        f[29] = sld.length.toFloat()                                // sld_length
        f[30] = host.count { !it.isLetterOrDigit() && it != '.' && it != '-' }.toFloat() // num_special_chars_in_domain
        f[31] = entropy(path)                                       // path_entropy
        f[32] = if (Regex("%[0-9a-fA-F]{2}").containsMatchIn(url)) 1f else 0f  // has_hex_encoding

        val digitRuns = DIGIT_RUN_REGEX.findAll(host)
        f[33] = (digitRuns.maxOfOrNull { it.value.length } ?: 0).toFloat()  // consecutive_digits_in_domain
        f[34] = if (TLD_IN_PATH_REGEX.containsMatchIn(path)) 1f else 0f     // has_tld_in_path

        return f
    }

    private fun entropy(s: String): Float {
        if (s.isEmpty()) return 0f
        val freq = HashMap<Char, Int>()
        for (c in s) freq[c] = (freq[c] ?: 0) + 1
        val n = s.length.toDouble()
        return freq.values.sumOf { count ->
            val p = count / n
            -p * (ln(p) / ln(2.0))
        }.toFloat()
    }

    private fun isIpAddress(host: String): Boolean {
        if (host.isEmpty()) return false
        // IPv4
        val ipv4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        if (ipv4.matches(host)) return true
        // IPv6 (bracketed)
        if (host.startsWith('[') && host.endsWith(']')) return true
        return false
    }
}
