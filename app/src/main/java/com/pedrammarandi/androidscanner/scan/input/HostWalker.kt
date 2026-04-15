package com.pedrammarandi.androidscanner.scan.input

import com.pedrammarandi.androidscanner.scan.model.PrefixEntry

class HostWalker {
    fun estimateTargets(entries: List<PrefixEntry>, limit: Long = Long.MAX_VALUE): Long {
        val total = entries.sumOf { it.scanHosts }
        return minOf(total, limit)
    }

    suspend fun walk(
        entries: List<PrefixEntry>,
        limit: Long = Long.MAX_VALUE,
        onHost: suspend (address: String, prefix: String) -> Boolean,
    ): Long {
        var emitted = 0L

        for (entry in entries) {
            val prefix = try {
                Ipv4Math.parsePrefix(entry.prefix)
            } catch (error: IllegalArgumentException) {
                throw IllegalStateException("Unable to parse stored prefix ${entry.prefix}", error)
            }

            val bounds = prefix.hostBounds() ?: continue
            for (rawAddress in bounds) {
                if (emitted >= limit) {
                    return emitted
                }
                if (!onHost(Ipv4Math.formatAddress(rawAddress), entry.prefix)) {
                    return emitted
                }
                emitted += 1
            }
        }

        return emitted
    }
}

