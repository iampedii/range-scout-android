package com.pedrammarandi.androidscanner.scan.runtime

import android.content.Context
import android.content.SharedPreferences
import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft
import com.pedrammarandi.androidscanner.scan.model.ScanTransport

class SharedPreferencesScanProfileStore(
    context: Context,
) : ScanProfileStore {
    private val preferences: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun load(): ScannerProfile? {
        if (!preferences.getBoolean(KEY_PROFILE_SAVED, false)) {
            return null
        }

        val defaultScan = ScanConfigDraft()
        val defaultDnstt = DnsttConfigDraft()

        return ScannerProfile(
            scanConfigDraft = ScanConfigDraft(
                workers = preferences.getString(KEY_SCAN_WORKERS, defaultScan.workers).orEmpty(),
                timeoutMillis = preferences.getString(KEY_SCAN_TIMEOUT_MILLIS, defaultScan.timeoutMillis).orEmpty(),
                port = preferences.getString(KEY_SCAN_PORT, defaultScan.port).orEmpty(),
                protocol = preferences.getString(KEY_SCAN_PROTOCOL, defaultScan.protocol.name)
                    ?.toEnumOrDefault(defaultScan.protocol)
                    ?: defaultScan.protocol,
                probeDomain = migrateLegacyProbeDomain(
                    preferences.getString(KEY_SCAN_PROBE_DOMAIN, defaultScan.probeDomain).orEmpty(),
                    defaultScan.probeDomain,
                ),
                querySize = preferences.getString(KEY_SCAN_QUERY_SIZE, defaultScan.querySize).orEmpty(),
                scoreThreshold = preferences.getString(KEY_SCAN_SCORE_THRESHOLD, defaultScan.scoreThreshold).orEmpty(),
            ),
            dnsttConfigDraft = DnsttConfigDraft(
                workers = preferences.getString(KEY_DNSTT_WORKERS, defaultDnstt.workers).orEmpty(),
                timeoutMillis = preferences.getString(KEY_DNSTT_TIMEOUT_MILLIS, defaultDnstt.timeoutMillis).orEmpty(),
                transport = preferences.getString(KEY_DNSTT_TRANSPORT, defaultDnstt.transport.name)
                    ?.toEnumOrDefault(defaultDnstt.transport)
                    ?: defaultDnstt.transport,
                domain = preferences.getString(KEY_DNSTT_DOMAIN, defaultDnstt.domain).orEmpty(),
                pubkey = preferences.getString(KEY_DNSTT_PUBKEY, defaultDnstt.pubkey).orEmpty(),
                e2eTimeoutSeconds = preferences.getString(KEY_DNSTT_E2E_TIMEOUT_SECONDS, defaultDnstt.e2eTimeoutSeconds).orEmpty(),
                e2eUrl = preferences.getString(KEY_DNSTT_E2E_URL, defaultDnstt.e2eUrl).orEmpty(),
                socksUsername = preferences.getString(KEY_DNSTT_SOCKS_USERNAME, defaultDnstt.socksUsername).orEmpty(),
                socksPassword = preferences.getString(KEY_DNSTT_SOCKS_PASSWORD, defaultDnstt.socksPassword).orEmpty(),
                testNearbyIps = preferences.getBoolean(KEY_DNSTT_TEST_NEARBY_IPS, defaultDnstt.testNearbyIps),
            ),
        )
    }

    override fun save(profile: ScannerProfile) {
        check(
            preferences.edit()
                .putBoolean(KEY_PROFILE_SAVED, true)
                .putString(KEY_SCAN_WORKERS, profile.scanConfigDraft.workers)
                .putString(KEY_SCAN_TIMEOUT_MILLIS, profile.scanConfigDraft.timeoutMillis)
                .putString(KEY_SCAN_PORT, profile.scanConfigDraft.port)
                .putString(KEY_SCAN_PROTOCOL, profile.scanConfigDraft.protocol.name)
                .putString(KEY_SCAN_PROBE_DOMAIN, profile.scanConfigDraft.probeDomain)
                .putString(KEY_SCAN_QUERY_SIZE, profile.scanConfigDraft.querySize)
                .putString(KEY_SCAN_SCORE_THRESHOLD, profile.scanConfigDraft.scoreThreshold)
                .putString(KEY_DNSTT_WORKERS, profile.dnsttConfigDraft.workers)
                .putString(KEY_DNSTT_TIMEOUT_MILLIS, profile.dnsttConfigDraft.timeoutMillis)
                .putString(KEY_DNSTT_TRANSPORT, profile.dnsttConfigDraft.transport.name)
                .putString(KEY_DNSTT_DOMAIN, profile.dnsttConfigDraft.domain)
                .putString(KEY_DNSTT_PUBKEY, profile.dnsttConfigDraft.pubkey)
                .putString(KEY_DNSTT_E2E_TIMEOUT_SECONDS, profile.dnsttConfigDraft.e2eTimeoutSeconds)
                .putString(KEY_DNSTT_E2E_URL, profile.dnsttConfigDraft.e2eUrl)
                .putString(KEY_DNSTT_SOCKS_USERNAME, profile.dnsttConfigDraft.socksUsername)
                .putString(KEY_DNSTT_SOCKS_PASSWORD, profile.dnsttConfigDraft.socksPassword)
                .putBoolean(KEY_DNSTT_TEST_NEARBY_IPS, profile.dnsttConfigDraft.testNearbyIps)
                .commit(),
        ) {
            "Unable to save profile."
        }
    }

    private inline fun <reified T : Enum<T>> String.toEnumOrDefault(defaultValue: T): T {
        return enumValues<T>().firstOrNull { it.name == this } ?: defaultValue
    }

    private fun migrateLegacyProbeDomain(value: String, defaultValue: String): String {
        return if (value == LEGACY_SCAN_PROBE_DOMAIN) defaultValue else value
    }

    private companion object {
        private const val PREFS_NAME = "scanner_profile"
        private const val LEGACY_SCAN_PROBE_DOMAIN = "1.1.1.1"
        private const val KEY_PROFILE_SAVED = "profile_saved"

        private const val KEY_SCAN_WORKERS = "scan_workers"
        private const val KEY_SCAN_TIMEOUT_MILLIS = "scan_timeout_millis"
        private const val KEY_SCAN_PORT = "scan_port"
        private const val KEY_SCAN_PROTOCOL = "scan_protocol"
        private const val KEY_SCAN_PROBE_DOMAIN = "scan_probe_domain"
        private const val KEY_SCAN_QUERY_SIZE = "scan_query_size"
        private const val KEY_SCAN_SCORE_THRESHOLD = "scan_score_threshold"

        private const val KEY_DNSTT_WORKERS = "dnstt_workers"
        private const val KEY_DNSTT_TIMEOUT_MILLIS = "dnstt_timeout_millis"
        private const val KEY_DNSTT_TRANSPORT = "dnstt_transport"
        private const val KEY_DNSTT_DOMAIN = "dnstt_domain"
        private const val KEY_DNSTT_PUBKEY = "dnstt_pubkey"
        private const val KEY_DNSTT_E2E_TIMEOUT_SECONDS = "dnstt_e2e_timeout_seconds"
        private const val KEY_DNSTT_E2E_URL = "dnstt_e2e_url"
        private const val KEY_DNSTT_SOCKS_USERNAME = "dnstt_socks_username"
        private const val KEY_DNSTT_SOCKS_PASSWORD = "dnstt_socks_password"
        private const val KEY_DNSTT_TEST_NEARBY_IPS = "dnstt_test_nearby_ips"
    }
}
