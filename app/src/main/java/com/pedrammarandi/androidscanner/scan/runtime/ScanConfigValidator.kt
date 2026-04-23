package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.ScanConfig
import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft
import java.net.URI

internal const val maxDnsScanWorkers = 64
internal const val maxDnsttWorkers = 32
internal const val minDnsTimeoutMillis = 500
internal const val maxDnsTimeoutMillis = 60_000

object ScanConfigValidator {
    fun validate(draft: ScanConfigDraft): Result<ScanConfig> = runCatching {
        val requestedWorkers = draft.workers.trim().toIntOrNull()
            ?.takeIf { it > 0 }
            ?: error("Workers must be a positive integer.")
        val workers = requestedWorkers.coerceAtMost(maxScanWorkers)

        val requestedTimeoutMillis = draft.timeoutMillis.trim().toIntOrNull()
            ?.takeIf { it > 0 }
            ?: error("Timeout must be a positive integer in milliseconds.")
        val timeoutMillis = requestedTimeoutMillis.coerceIn(minDnsTimeoutMillis, maxDnsTimeoutMillis)

        val port = draft.port.trim().toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: error("Port must be between 1 and 65535.")

        val querySize = if (draft.querySize.trim().isEmpty()) {
            0
        } else {
            draft.querySize.trim().toIntOrNull()
                ?.takeIf { it >= 0 }
                ?: error("Query size must be zero or greater.")
        }

        val scoreThreshold = draft.scoreThreshold.trim().toIntOrNull()
            ?.takeIf { it in 1..6 }
            ?: error("Score threshold must be between 1 and 6.")

        ScanConfig(
            workers = workers,
            timeoutMillis = timeoutMillis,
            port = port,
            protocol = draft.protocol,
            probeDomain = normalizeProbeDomain(draft.probeDomain),
            querySize = querySize,
            scoreThreshold = scoreThreshold,
        )
    }

    private fun normalizeProbeDomain(rawInput: String): String {
        val trimmed = rawInput.trim()
        require(trimmed.isNotEmpty()) { "Probe domain is required." }

        val candidate = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val uri = try {
            URI(candidate)
        } catch (_: Exception) {
            throw IllegalArgumentException("Enter a valid probe URL or hostname.")
        }

        val host = uri.host?.trim()?.trimEnd('.')
            ?: throw IllegalArgumentException("Enter a valid probe URL or hostname.")

        require(host.isNotEmpty()) { "Enter a valid probe URL or hostname." }
        return host.lowercase()
    }

    private const val maxScanWorkers = maxDnsScanWorkers
}
