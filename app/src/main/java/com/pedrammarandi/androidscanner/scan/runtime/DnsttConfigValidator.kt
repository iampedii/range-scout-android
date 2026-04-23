package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.DnsttConfig
import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import java.net.URI

object DnsttConfigValidator {
    fun validate(draft: DnsttConfigDraft): Result<DnsttConfig> = runCatching {
        val workers = draft.workers.trim().toIntOrNull()
            ?.takeIf { it > 0 }
            ?: error("DNSTT workers must be a positive integer.")
        val boundedWorkers = workers.coerceAtMost(maxDnsttWorkers)

        val timeoutMillis = draft.timeoutMillis.trim().toIntOrNull()
            ?.takeIf { it > 0 }
            ?: error("DNSTT timeout must be a positive integer in milliseconds.")

        val domain = normalizeDomain(draft.domain)
        val pubkey = draft.pubkey.trim()
        val socksUsername = draft.socksUsername.trim()
        val socksPassword = draft.socksPassword

        if (pubkey.isNotEmpty()) {
            draft.e2eTimeoutSeconds.trim().toIntOrNull()
                ?.takeIf { it > 0 }
                ?: error("DNSTT E2E timeout must be a positive integer in seconds.")
        }

        if (socksPassword.isNotBlank() && socksUsername.isEmpty()) {
            error("DNSTT SOCKS password requires a SOCKS username.")
        }

        val e2eUrl = draft.e2eUrl.trim()
        if (pubkey.isNotEmpty()) {
            val uri = try {
                URI(e2eUrl)
            } catch (_: Exception) {
                null
            } ?: error("DNSTT E2E URL must be a valid http or https URL.")

            if (uri.scheme !in setOf("http", "https") || uri.host.isNullOrBlank()) {
                error("DNSTT E2E URL must use http or https.")
            }
        }

        DnsttConfig(
            workers = boundedWorkers,
            timeoutMillis = timeoutMillis,
            transport = draft.transport,
            domain = domain,
            pubkey = pubkey,
            e2eTimeoutSeconds = draft.e2eTimeoutSeconds.trim().toIntOrNull() ?: 25,
            e2eUrl = e2eUrl,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            testNearbyIps = draft.testNearbyIps,
        )
    }

    private fun normalizeDomain(rawInput: String): String {
        val trimmed = rawInput.trim()
        require(trimmed.isNotEmpty()) { "DNSTT domain is required." }

        val candidate = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val uri = try {
            URI(candidate)
        } catch (_: Exception) {
            throw IllegalArgumentException("Enter a valid DNSTT domain or hostname.")
        }

        val host = uri.host?.trim()?.trimEnd('.')
            ?: throw IllegalArgumentException("Enter a valid DNSTT domain or hostname.")

        require(host.isNotEmpty()) { "Enter a valid DNSTT domain or hostname." }
        return host.lowercase()
    }
}
