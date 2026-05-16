package com.safelink.ml

import android.net.Uri
import kotlin.math.ln

/**
 * Mirrors Python feature_extractor.py — computes all 22 URL features (PRD v5.1).
 * n_features = 22 LOCKED — index order must match FEATURE_COLUMNS in feature_extractor.py.
 *
 * Feature index map (0-based):
 *   0  host_length         7  is_https            14 digit_ratio
 *   1  path_length         8  has_ip_host         15 special_char_ratio
 *   2  query_length        9  has_at_in_url       16 host_entropy
 *   3  num_dots           10  has_homoglyphs      17 path_entropy
 *   4  num_hyphens        11  has_hex_encoding    18 min_brand_distance
 *   5  num_query_params   12  is_url_shortener    19 brand_in_subdomain
 *   6  num_subdomains     13  is_suspicious_tld   20 url_depth
 *                                                 21 has_punycode
 */
object FeatureExtractor {

    private val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "club", "online", "site", "info", "biz", "tk", "ml",
        "ga", "cf", "gq", "click", "link", "download", "win", "loan", "work",
        "review", "stream", "gdn", "racing", "accountant", "science", "date",
        "faith", "party", "trade", "webcam", "cricket", "bid", "rocks",
    )

    private val BRAND_KEYWORDS = setOf(
        "hnb", "sampath", "boc", "combank", "commercial", "dialog", "mobitel", "slt",
        "peoples", "bank", "lankabell",
        "paypal", "amazon", "google", "facebook", "apple", "microsoft",
        "netflix", "instagram", "whatsapp", "dhl", "ebay", "linkedin",
        "twitter", "youtube", "dropbox", "adobe", "office", "outlook",
        "icloud", "appleid", "itunes", "appstore",
    )

    private val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "tiny.cc", "qr.ae", "bc.vc", "su.pr",
    )

    private val HEX_ENCODING_REGEX = Regex("""%[0-9a-fA-F]{2}""")
    private val NORMAL_URL_CHARS   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/:?=&#%+@~".toSet()

    fun extract(url: String): FloatArray {
        val f = FloatArray(22) { 0f }

        val normalized = if ("://" !in url) "http://$url" else url
        val uri = runCatching { Uri.parse(normalized) }.getOrNull()

        val scheme = uri?.scheme ?: "http"
        val host   = uri?.host?.lowercase() ?: ""
        val path   = uri?.path ?: ""
        val query  = uri?.query ?: ""

        // Host decomposition — strip www.
        val domainNoWww = host.removePrefix("www.")
        val parts       = domainNoWww.split('.')
        val tld         = if (parts.size > 1) parts.last() else ""
        val subdomain   = if (parts.size > 2) parts.dropLast(2).joinToString(".") else ""

        // --- Feature computation ---

        f[0]  = host.length.toFloat()                           // host_length
        f[1]  = path.length.toFloat()                           // path_length
        f[2]  = query.length.toFloat()                          // query_length
        f[3]  = url.count { it == '.' }.toFloat()               // num_dots
        f[4]  = host.count { it == '-' }.toFloat()              // num_hyphens (host only)
        f[5]  = (uri?.queryParameterNames?.size ?: 0).toFloat() // num_query_params
        f[6]  = (if (subdomain.isEmpty()) 0 else subdomain.split('.').size).toFloat() // num_subdomains
        f[7]  = if (scheme == "https") 1f else 0f               // is_https
        f[8]  = if (isIpAddress(host)) 1f else 0f               // has_ip_host
        f[9]  = if ('@' in url) 1f else 0f                      // has_at_in_url

        // has_homoglyphs — non-ASCII Unicode letters in hostname (IDN homoglyph attacks)
        f[10] = if (host.any { it.code > 127 && it.isLetter() }) 1f else 0f

        f[11] = if (HEX_ENCODING_REGEX.containsMatchIn(url)) 1f else 0f  // has_hex_encoding
        f[12] = if (URL_SHORTENERS.any { host == it || host.endsWith(".$it") }) 1f else 0f  // is_url_shortener
        f[13] = if (tld in SUSPICIOUS_TLDS) 1f else 0f          // is_suspicious_tld

        // digit_ratio — digits in hostname / len(hostname)
        f[14] = if (host.isNotEmpty())
            host.count { it.isDigit() }.toFloat() / host.length
        else 0f

        // special_char_ratio — chars outside normal URL charset / len(url)
        f[15] = if (url.isNotEmpty())
            url.count { it !in NORMAL_URL_CHARS }.toFloat() / url.length
        else 0f

        f[16] = entropy(host)   // host_entropy
        f[17] = entropy(path)   // path_entropy

        // min_brand_distance — Levenshtein to nearest brand keyword (token length >= 4)
        f[18] = minBrandDistance(host)

        // brand_in_subdomain — any brand keyword in subdomain tokens
        f[19] = if (subdomain.isNotEmpty()) {
            val tokens = mutableSetOf<String>()
            for (part in subdomain.lowercase().split('.')) {
                if (part.isNotEmpty()) {
                    tokens.add(part)
                    if ('-' in part) tokens.addAll(part.split('-').filter { it.isNotEmpty() })
                }
            }
            if (BRAND_KEYWORDS.intersect(tokens).isNotEmpty()) 1f else 0f
        } else 0f

        // url_depth — number of non-empty path segments
        f[20] = path.split('/').count { it.isNotEmpty() }.toFloat()

        // has_punycode — xn-- prefix indicates IDN encoding
        f[21] = if ("xn--" in host.lowercase()) 1f else 0f

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
        if (Regex("""^\d{1,3}(\.\d{1,3}){3}$""").matches(host)) return true
        if (host.startsWith('[') && host.endsWith(']')) return true
        return false
    }

    private fun levenshtein(a: String, b: String): Int {
        val dp = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) dp[i][0] = i
        for (j in 0..b.length) dp[0][j] = j
        for (i in 1..a.length) {
            for (j in 1..b.length) {
                dp[i][j] = minOf(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1
                )
            }
        }
        return dp[a.length][b.length]
    }

    private fun minBrandDistance(host: String): Float {
        val tokens = host.lowercase().split('.', '-').filter { it.length >= 4 }
        val brands = BRAND_KEYWORDS.filter { it.length >= 4 }
        if (tokens.isEmpty() || brands.isEmpty()) return 10f
        return tokens.flatMap { t -> brands.map { b -> levenshtein(t, b) } }
            .min()
            .toFloat()
    }
}
