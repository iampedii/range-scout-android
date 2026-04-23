package com.pedrammarandi.androidscanner.scan.model

enum class ScanTransport {
    UDP,
    TCP,
    BOTH,
}

enum class DnsttTransport {
    UDP,
    TCP,
}

data class ScanConfigDraft(
    val workers: String = "8",
    val timeoutMillis: String = "15000",
    val port: String = "53",
    val protocol: ScanTransport = ScanTransport.UDP,
    val probeDomain: String = "example.com",
    val querySize: String = "",
    val scoreThreshold: String = "2",
)

data class ScanConfig(
    val workers: Int,
    val timeoutMillis: Int,
    val port: Int,
    val protocol: ScanTransport,
    val probeDomain: String,
    val querySize: Int,
    val scoreThreshold: Int,
)

data class DnsttConfigDraft(
    val workers: String = "8",
    val timeoutMillis: String = "5000",
    val transport: DnsttTransport = DnsttTransport.UDP,
    val domain: String = "1.1.1.1",
    val pubkey: String = "",
    val e2eTimeoutSeconds: String = "25",
    val e2eUrl: String = "https://1.1.1.1/cdn-cgi/trace",
    val socksUsername: String = "",
    val socksPassword: String = "",
    val testNearbyIps: Boolean = false,
)

data class DnsttConfig(
    val workers: Int,
    val timeoutMillis: Int,
    val transport: DnsttTransport,
    val domain: String,
    val pubkey: String,
    val e2eTimeoutSeconds: Int,
    val e2eUrl: String,
    val socksUsername: String,
    val socksPassword: String,
    val testNearbyIps: Boolean,
)

data class PrefixEntry(
    val prefix: String,
    val sourceLabel: String,
    val sourceAsns: List<String>,
    val totalAddresses: Long,
    val scanHosts: Long,
)

data class ResolverRecord(
    val ip: String,
    val transport: ScanTransport,
    val prefix: String,
    val dnsReachable: Boolean,
    val scanStatus: String,
    val scanError: String? = null,
    val recursionAdvertised: Boolean = false,
    val qualifiedForTunnel: Boolean = false,
    val stable: Boolean = false,
    val responseCode: String = "",
    val latencyMillis: Long = 0,
    val tunnelScore: Int = 0,
    val tunnelNsSupport: Boolean = false,
    val tunnelTxtSupport: Boolean = false,
    val tunnelRandomSub: Boolean = false,
    val tunnelRealism: Boolean = false,
    val tunnelEdns0Support: Boolean = false,
    val tunnelEdnsMaxPayload: Int = 0,
    val tunnelNxdomain: Boolean = false,
    val dnsttNearby: Boolean = false,
    val dnsttChecked: Boolean = false,
    val dnsttTunnelOk: Boolean = false,
    val dnsttE2eOk: Boolean = false,
    val dnsttTunnelMillis: Long = 0,
    val dnsttE2eMillis: Long = 0,
    val dnsttError: String = "",
)

data class FailureRecord(
    val ip: String,
    val prefix: String,
    val reason: String,
)

enum class SessionStatus {
    IDLE,
    READY,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED,
}

enum class ScannerPage {
    SETUP,
    SCAN,
}

enum class SuccessSortOption {
    DNS_SCORE,
    TUNNEL_SPEED,
    E2E_SPEED,
}

enum class DnsttSortOption {
    TUNNEL_SPEED,
    E2E_SPEED,
}

data class ScanProgress(
    val scanned: Long = 0,
    val total: Long = 0,
    val working: Long = 0,
    val compatible: Long = 0,
    val qualified: Long = 0,
)

data class DnsttProgress(
    val checked: Long = 0,
    val total: Long = 0,
    val tunnelOk: Long = 0,
    val e2eOk: Long = 0,
)

data class ScannerUiState(
    val currentPage: ScannerPage = ScannerPage.SETUP,
    val showAdvancedConfig: Boolean = false,
    val targetInput: String = "",
    val targetsDirty: Boolean = false,
    val parsedTargets: List<PrefixEntry> = emptyList(),
    val parseWarnings: List<String> = emptyList(),
    val totalAddresses: Long = 0,
    val totalScanHosts: Long = 0,
    val configDraft: ScanConfigDraft = ScanConfigDraft(),
    val sessionStatus: SessionStatus = SessionStatus.IDLE,
    val progress: ScanProgress = ScanProgress(),
    val successSort: SuccessSortOption = SuccessSortOption.DNS_SCORE,
    val resolvers: List<ResolverRecord> = emptyList(),
    val resolverVisibleLimit: Int = 10,
    val resolverCount: Long = 0,
    val failures: List<FailureRecord> = emptyList(),
    val failureCount: Long = 0,
    val dnsttConfigDraft: DnsttConfigDraft = DnsttConfigDraft(),
    val dnsttSessionStatus: SessionStatus = SessionStatus.IDLE,
    val dnsttProgress: DnsttProgress = DnsttProgress(),
    val dnsttSort: DnsttSortOption = DnsttSortOption.TUNNEL_SPEED,
    val dnsttResolvers: List<ResolverRecord> = emptyList(),
    val dnsttResolverVisibleLimit: Int = 10,
    val dnsttResolverCount: Long = 0,
    val dnsttFailures: List<ResolverRecord> = emptyList(),
    val dnsttFailureVisibleLimit: Int = 10,
    val dnsttFailureCount: Long = 0,
    val activityLog: List<String> = listOf(
        "DNS scan runtime ready. Load targets to begin.",
    ),
    val lastError: String? = null,
    val dnsttLastError: String? = null,
    val transparentProxyDetected: Boolean = false,
)

data class ScanRuntimeRequest(
    val config: ScanConfig,
    val targets: List<PrefixEntry>,
    val totalTargets: Long,
)

data class DnsttRuntimeRequest(
    val scanConfig: ScanConfig,
    val dnsttConfig: DnsttConfig,
    val resolvers: List<ResolverRecord>,
    val basePrefixes: List<String>,
)
