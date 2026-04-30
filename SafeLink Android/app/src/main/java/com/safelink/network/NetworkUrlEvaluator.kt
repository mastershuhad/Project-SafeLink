package com.safelink.network

/**
 * Evaluates URLs targeting private/local networks.
 *
 * - Private IPs (RFC 1918 + localhost + .local/.lan/.home) with clean paths → CLEAN
 * - Private IPs with phishing path vocabulary → SUSPICIOUS
 * - Public hosts → NOT_LOCAL
 */
object NetworkUrlEvaluator {

    enum class Result { NOT_LOCAL, CLEAN, SUSPICIOUS }

    private val PRIVATE_RANGES = listOf(
        Regex("""^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""),
        Regex("""^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$"""),
        Regex("""^192\.168\.\d{1,3}\.\d{1,3}$"""),
        Regex("""^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""),
        Regex("""^::1$"""),
    )

    private val LOCAL_TLD_SUFFIXES = listOf(".local", ".lan", ".home", ".internal", ".intranet")

    private val PHISHING_PATH_WORDS = setOf(
        "login", "signin", "account", "verify", "secure", "password", "credential",
        "banking", "payment", "update", "confirm", "suspend", "alert", "admin",
    )

    fun evaluate(host: String, path: String): Result {
        if (!isPrivateHost(host)) return Result.NOT_LOCAL

        val pathLower = path.lowercase()
        val hasPhishingWord = PHISHING_PATH_WORDS.any { word -> word in pathLower }

        return if (hasPhishingWord) Result.SUSPICIOUS else Result.CLEAN
    }

    fun isPrivateHost(host: String): Boolean {
        val h = host.lowercase().removePrefix("www.")
        if (PRIVATE_RANGES.any { it.matches(h) }) return true
        if (h == "localhost") return true
        if (LOCAL_TLD_SUFFIXES.any { h.endsWith(it) }) return true
        return false
    }
}
