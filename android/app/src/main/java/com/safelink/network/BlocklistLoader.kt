package com.safelink.network

import android.content.Context

object BlocklistLoader {

    fun loadBlocklist(context: Context): HashSet<String> {
        return loadLines(context, "blocklist.txt", initialCapacity = 200_000)
    }

    fun loadWhitelist(context: Context): HashSet<String> {
        return loadLines(context, "whitelist.txt", initialCapacity = 256)
    }

    private fun loadLines(context: Context, filename: String, initialCapacity: Int): HashSet<String> {
        val set = HashSet<String>(initialCapacity)
        try {
            context.assets.open(filename).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && !trimmed.startsWith('#')) {
                        set.add(trimmed.lowercase())
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("BlocklistLoader", "Failed to load $filename: ${e.message}")
        }
        return set
    }
}
