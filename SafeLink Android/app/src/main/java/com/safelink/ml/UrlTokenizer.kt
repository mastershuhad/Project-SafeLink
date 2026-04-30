package com.safelink.ml

object UrlTokenizer {

    const val SEQ_LEN = 200

    /**
     * Mirrors Python encode_url(): maps each character to (code - 31).coerceIn(1, 99),
     * pads/truncates to SEQ_LEN=200.
     */
    fun encode(url: String): IntArray {
        val result = IntArray(SEQ_LEN)
        val limit = minOf(url.length, SEQ_LEN)
        for (i in 0 until limit) {
            result[i] = (url[i].code - 31).coerceIn(1, 99)
        }
        // Remaining positions are 0 (padding) by default
        return result
    }
}
