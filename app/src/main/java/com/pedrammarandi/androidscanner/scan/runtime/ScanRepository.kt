package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.input.TargetParseResult
import com.pedrammarandi.androidscanner.scan.input.TargetParser
import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import com.pedrammarandi.androidscanner.scan.model.DnsttProgress
import com.pedrammarandi.androidscanner.scan.model.DnsttRuntimeRequest
import com.pedrammarandi.androidscanner.scan.model.DnsttSortOption
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft
import com.pedrammarandi.androidscanner.scan.model.ScanProgress
import com.pedrammarandi.androidscanner.scan.model.ScannerPage
import com.pedrammarandi.androidscanner.scan.model.ScanRuntimeRequest
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import com.pedrammarandi.androidscanner.scan.model.ScannerUiState
import com.pedrammarandi.androidscanner.scan.model.SessionStatus
import com.pedrammarandi.androidscanner.scan.model.SuccessSortOption
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.Comparator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

private data class DnsttResultPreviews(
    val successes: List<ResolverRecord>,
    val successCount: Long,
    val failures: List<ResolverRecord>,
    val failureCount: Long,
)

class ScanRepository(
    private val targetParser: TargetParser,
    private val profileStore: ScanProfileStore = NoOpScanProfileStore,
) {
    private val resultLock = Any()
    private val resolverRecords = mutableListOf<ResolverRecord>()
    private val failureRecords = mutableListOf<FailureRecord>()
    private val dnsttResolverRecords = mutableListOf<ResolverRecord>()
    private val _state = MutableStateFlow(ScannerUiState())
    val state: StateFlow<ScannerUiState> = _state.asStateFlow()

    init {
        profileStore.load()?.let { profile ->
            _state.update { current ->
                current.copy(
                    configDraft = sanitizeScanDraft(profile.scanConfigDraft),
                    dnsttConfigDraft = profile.dnsttConfigDraft,
                    activityLog = appendLog(current.activityLog, "Loaded saved profile"),
                )
            }
        }
    }

    fun updateTargetInput(value: String) {
        _state.update {
            it.copy(
                targetInput = value,
                targetsDirty = true,
            )
        }
    }

    fun importWhiteDnsList(option: WhiteDnsListOption) {
        _state.update { current ->
            current.copy(
                targetInput = WhiteDnsLists.targetsFor(option),
                targetsDirty = true,
                configDraft = current.configDraft.copy(protocol = option.transport),
                activityLog = appendLog(current.activityLog, "Imported ${option.label}"),
            )
        }
    }

    fun updateWorkers(value: String) =
        updateDraft { copy(workers = sanitizeIntegerInput(value, minValue = 1, maxValue = maxDnsScanWorkers)) }

    fun updateTimeoutMillis(value: String) =
        updateDraft {
            copy(
                timeoutMillis = sanitizeIntegerInput(
                    value = value,
                    minValue = minDnsTimeoutMillis,
                    maxValue = maxDnsTimeoutMillis,
                ),
            )
        }

    fun updatePort(value: String) =
        updateDraft { copy(port = sanitizeIntegerInput(value, minValue = 1, maxValue = 65_535)) }

    fun updateProbeDomain(value: String) = updateDraft { copy(probeDomain = value) }

    fun updateScoreThreshold(value: String) =
        updateDraft { copy(scoreThreshold = sanitizeIntegerInput(value, minValue = 1, maxValue = 6)) }

    fun updateProtocol(value: ScanTransport) = updateDraft { copy(protocol = value) }

    fun updateSuccessSort(value: SuccessSortOption) {
        val visibleLimit = _state.value.resolverVisibleLimit
        val preview = synchronized(resultLock) {
            buildResolverPreviewLocked(value, visibleLimit)
        }

        _state.update {
            it.copy(
                successSort = value,
                resolvers = preview,
            )
        }
    }

    fun updateDnsttSort(value: DnsttSortOption) {
        val snapshot = _state.value
        val preview = synchronized(resultLock) {
            buildDnsttResultPreviewsLocked(
                sort = value,
                e2eRequested = snapshot.dnsttConfigDraft.pubkey.isNotBlank(),
                successLimit = snapshot.dnsttResolverVisibleLimit,
                failureLimit = snapshot.dnsttFailureVisibleLimit,
            )
        }

        _state.update {
            it.copy(
                dnsttSort = value,
                dnsttResolvers = preview.successes,
                dnsttResolverCount = preview.successCount,
                dnsttFailures = preview.failures,
                dnsttFailureCount = preview.failureCount,
            )
        }
    }

    fun updateDnsttWorkers(value: String) = updateDnsttDraft { copy(workers = value) }

    fun updateDnsttTimeoutMillis(value: String) = updateDnsttDraft { copy(timeoutMillis = value) }

    fun updateDnsttTransport(value: DnsttTransport) = updateDnsttDraft { copy(transport = value) }

    fun updateDnsttDomain(value: String) = updateDnsttDraft { copy(domain = value) }

    fun updateDnsttPubkey(value: String) = updateDnsttDraft { copy(pubkey = value) }

    fun updateDnsttE2eTimeoutSeconds(value: String) = updateDnsttDraft { copy(e2eTimeoutSeconds = value) }

    fun updateDnsttE2eUrl(value: String) = updateDnsttDraft { copy(e2eUrl = value) }

    fun updateDnsttSocksUsername(value: String) = updateDnsttDraft { copy(socksUsername = value) }

    fun updateDnsttSocksPassword(value: String) = updateDnsttDraft { copy(socksPassword = value) }

    fun toggleDnsttNearbyIps() = updateDnsttDraft { copy(testNearbyIps = !testNearbyIps) }

    fun toggleAdvancedConfig() {
        _state.update { it.copy(showAdvancedConfig = !it.showAdvancedConfig) }
    }

    fun showSetupPage() {
        _state.update { it.copy(currentPage = ScannerPage.SETUP) }
    }

    fun showScanPage() {
        _state.update { it.copy(currentPage = ScannerPage.SCAN) }
    }

    fun loadTargets(): Boolean {
        val parseResult = targetParser.parse(_state.value.targetInput)
        applyParseResult(parseResult)
        return parseResult.entries.isNotEmpty()
    }

    fun saveProfile(): Result<Unit> {
        val snapshot = _state.value
        return runCatching {
            profileStore.save(
                ScannerProfile(
                    scanConfigDraft = snapshot.configDraft,
                    dnsttConfigDraft = snapshot.dnsttConfigDraft,
                ),
            )
        }.onSuccess {
            _state.update { current ->
                current.copy(activityLog = appendLog(current.activityLog, "Saved profile"))
            }
        }
    }

    fun buildRuntimeRequest(): Result<ScanRuntimeRequest> {
        val snapshot = _state.value
        if (snapshot.parsedTargets.isEmpty()) {
            return Result.failure(IllegalStateException("Load targets before starting a scan."))
        }

        return ScanConfigValidator.validate(snapshot.configDraft).map { config ->
            ScanRuntimeRequest(
                config = config,
                targets = snapshot.parsedTargets,
                totalTargets = snapshot.totalScanHosts,
            )
        }.onFailure { error ->
            _state.update {
                it.copy(
                    lastError = error.message,
                    activityLog = appendLog(it.activityLog, "Config validation failed"),
                )
            }
        }
    }

    fun buildDnsttRuntimeRequest(): Result<DnsttRuntimeRequest> {
        val snapshot = _state.value
        val resolverSnapshot = snapshotResolvers()
        val baseScanConfig = ScanConfigValidator.validate(snapshot.configDraft).getOrElse { error ->
            _state.update {
                it.copy(
                    dnsttLastError = error.message,
                    activityLog = appendLog(it.activityLog, "DNSTT config validation failed"),
                )
            }
            return Result.failure(error)
        }

        val dnsttConfig = DnsttConfigValidator.validate(snapshot.dnsttConfigDraft).getOrElse { error ->
            _state.update {
                it.copy(
                    dnsttLastError = error.message,
                    activityLog = appendLog(it.activityLog, "DNSTT config validation failed"),
                )
            }
            return Result.failure(error)
        }

        val candidates = resolverSnapshot.filter { it.qualifiedForTunnel }
        if (candidates.isEmpty()) {
            val error = IllegalStateException("No score-qualified resolvers are available for DNSTT testing.")
            _state.update {
                it.copy(
                    dnsttLastError = error.message,
                    activityLog = appendLog(it.activityLog, "DNSTT requested with no qualified resolvers"),
                )
            }
            return Result.failure(error)
        }

        return Result.success(
            DnsttRuntimeRequest(
                scanConfig = baseScanConfig,
                dnsttConfig = dnsttConfig,
                resolvers = resolverSnapshot,
                basePrefixes = snapshot.parsedTargets.map { it.prefix },
            ),
        )
    }

    fun markScanRunning(request: ScanRuntimeRequest) {
        synchronized(resultLock) {
            resolverRecords.clear()
            failureRecords.clear()
            dnsttResolverRecords.clear()
        }
        _state.update {
            it.copy(
                currentPage = ScannerPage.SCAN,
                sessionStatus = SessionStatus.RUNNING,
                progress = ScanProgress(total = request.totalTargets),
                resolvers = emptyList(),
                resolverVisibleLimit = initialResultPreviewLimit,
                resolverCount = 0,
                failures = emptyList(),
                failureCount = 0,
                dnsttSessionStatus = SessionStatus.IDLE,
                dnsttProgress = DnsttProgress(),
                dnsttResolvers = emptyList(),
                dnsttResolverVisibleLimit = initialResultPreviewLimit,
                dnsttResolverCount = 0,
                dnsttFailures = emptyList(),
                dnsttFailureVisibleLimit = initialResultPreviewLimit,
                dnsttFailureCount = 0,
                lastError = null,
                dnsttLastError = null,
                transparentProxyDetected = false,
                activityLog = appendLog(
                    it.activityLog,
                    "Scan started for ${request.targets.size} target range(s)",
                ),
            )
        }
    }

    fun updateProgress(progress: ScanProgress) {
        _state.update { it.copy(progress = progress) }
    }

    fun appendResolver(resolver: ResolverRecord) = appendResolvers(listOf(resolver))

    fun appendResolvers(resolvers: Collection<ResolverRecord>) {
        if (resolvers.isEmpty()) {
            return
        }

        val snapshot = _state.value
        val currentSort = snapshot.successSort
        val currentPreview = snapshot.resolvers
        val currentVisibleLimit = snapshot.resolverVisibleLimit
        val preview = synchronized(resultLock) {
            resolverRecords.addAll(resolvers)
            mergeResolverPreview(
                currentPreview = currentPreview,
                additions = resolvers,
                comparator = comparatorFor(currentSort),
                limit = currentVisibleLimit,
            ) to resolverRecords.size.toLong()
        }

        _state.update {
            it.copy(
                resolvers = preview.first,
                resolverCount = preview.second,
            )
        }
    }

    fun appendFailure(failure: FailureRecord) = appendFailures(listOf(failure))

    fun appendFailures(failures: Collection<FailureRecord>) {
        if (failures.isEmpty()) {
            return
        }

        val visibleLimit = maxOf(_state.value.failures.size, resultPreviewLimit)
        val preview = synchronized(resultLock) {
            failureRecords.addAll(failures)
            failureRecords.take(visibleLimit) to failureRecords.size.toLong()
        }

        _state.update {
            it.copy(
                failures = preview.first,
                failureCount = preview.second,
            )
        }
    }

    fun loadMoreFailures() {
        val snapshot = _state.value
        val preview = synchronized(resultLock) {
            val nextLimit = nextVisibleLimit(
                currentLimit = snapshot.failures.size,
                totalCount = failureRecords.size,
            )
            failureRecords.take(nextLimit)
        }

        _state.update {
            it.copy(failures = preview)
        }
    }

    fun markDnsttRunning(request: DnsttRuntimeRequest) {
        synchronized(resultLock) {
            dnsttResolverRecords.clear()
        }
        _state.update {
            it.copy(
                dnsttSessionStatus = SessionStatus.RUNNING,
                dnsttProgress = DnsttProgress(
                    total = request.resolvers.count { resolver -> resolver.qualifiedForTunnel }.toLong(),
                ),
                dnsttSort = if (request.dnsttConfig.pubkey.isNotBlank()) {
                    DnsttSortOption.E2E_SPEED
                } else {
                    DnsttSortOption.TUNNEL_SPEED
                },
                dnsttResolvers = emptyList(),
                dnsttResolverVisibleLimit = initialResultPreviewLimit,
                dnsttResolverCount = 0,
                dnsttFailures = emptyList(),
                dnsttFailureVisibleLimit = initialResultPreviewLimit,
                dnsttFailureCount = 0,
                dnsttLastError = null,
                activityLog = appendLog(
                    it.activityLog,
                    "DNSTT started for ${request.resolvers.count { resolver -> resolver.qualifiedForTunnel }} candidate resolver(s)",
                ),
            )
        }
    }

    fun updateDnsttProgress(progress: DnsttProgress) {
        _state.update { it.copy(dnsttProgress = progress) }
    }

    fun upsertDnsttResolver(resolver: ResolverRecord) {
        val snapshot = _state.value
        val currentSort = snapshot.successSort
        val resolverVisibleLimit = snapshot.resolverVisibleLimit
        val dnsttSort = snapshot.dnsttSort
        val dnsttResolverVisibleLimit = snapshot.dnsttResolverVisibleLimit
        val dnsttFailureVisibleLimit = snapshot.dnsttFailureVisibleLimit
        val dnsttE2eRequested = snapshot.dnsttConfigDraft.pubkey.isNotBlank()
        val preview = synchronized(resultLock) {
            val existingIndex = dnsttResolverRecords.indexOfFirst {
                it.ip == resolver.ip && it.prefix == resolver.prefix && it.dnsttNearby == resolver.dnsttNearby
            }
            if (existingIndex >= 0) {
                dnsttResolverRecords[existingIndex] = resolver
            } else {
                dnsttResolverRecords += resolver
            }

            val resolverIndex = resolverRecords.indexOfFirst { existing ->
                matchesResolver(existing, resolver)
            }
            val resolverPreview = if (resolverIndex >= 0) {
                resolverRecords[resolverIndex] = resolver
                buildResolverPreviewLocked(currentSort, resolverVisibleLimit)
            } else {
                null
            }
            resolverPreview to
                buildDnsttResultPreviewsLocked(
                    sort = dnsttSort,
                    e2eRequested = dnsttE2eRequested,
                    successLimit = dnsttResolverVisibleLimit,
                    failureLimit = dnsttFailureVisibleLimit,
                )
        }

        _state.update { state ->
            state.copy(
                resolvers = preview.first ?: state.resolvers,
                dnsttResolvers = preview.second.successes,
                dnsttResolverCount = preview.second.successCount,
                dnsttFailures = preview.second.failures,
                dnsttFailureCount = preview.second.failureCount,
            )
        }
    }

    fun loadMoreResolvers() {
        val snapshot = _state.value
        val preview = synchronized(resultLock) {
            val nextLimit = nextVisibleLimit(
                currentLimit = snapshot.resolverVisibleLimit,
                totalCount = resolverRecords.size,
            )
            nextLimit to buildResolverPreviewLocked(snapshot.successSort, nextLimit)
        }

        _state.update {
            it.copy(
                resolverVisibleLimit = preview.first,
                resolvers = preview.second,
            )
        }
    }

    fun loadMoreDnsttResolvers() {
        val snapshot = _state.value
        val preview = synchronized(resultLock) {
            val e2eRequested = snapshot.dnsttConfigDraft.pubkey.isNotBlank()
            val nextLimit = nextVisibleLimit(
                currentLimit = snapshot.dnsttResolverVisibleLimit,
                totalCount = countDnsttSuccessesLocked(e2eRequested),
            )
            nextLimit to buildDnsttSuccessPreviewLocked(snapshot.dnsttSort, e2eRequested, nextLimit)
        }

        _state.update {
            it.copy(
                dnsttResolverVisibleLimit = preview.first,
                dnsttResolvers = preview.second,
            )
        }
    }

    fun loadMoreDnsttFailures() {
        val snapshot = _state.value
        val preview = synchronized(resultLock) {
            val e2eRequested = snapshot.dnsttConfigDraft.pubkey.isNotBlank()
            val nextLimit = nextVisibleLimit(
                currentLimit = snapshot.dnsttFailureVisibleLimit,
                totalCount = countDnsttFailuresLocked(e2eRequested),
            )
            nextLimit to buildDnsttFailurePreviewLocked(snapshot.dnsttSort, e2eRequested, nextLimit)
        }

        _state.update {
            it.copy(
                dnsttFailureVisibleLimit = preview.first,
                dnsttFailures = preview.second,
            )
        }
    }

    fun snapshotResolvers(): List<ResolverRecord> = snapshotResolvers(_state.value.successSort)

    fun snapshotResolvers(sort: SuccessSortOption): List<ResolverRecord> =
        synchronized(resultLock) {
            resolverRecords.sortedWith(comparatorFor(sort))
        }

    fun snapshotFailures(): List<FailureRecord> = synchronized(resultLock) { failureRecords.toList() }

    fun snapshotDnsttResolvers(): List<ResolverRecord> =
        synchronized(resultLock) {
            dnsttResolverRecords.sortedWith(dnsttComparatorFor(_state.value.dnsttSort))
        }

    fun markDnsttCompleted() {
        _state.update {
            it.copy(
                dnsttSessionStatus = SessionStatus.COMPLETED,
                activityLog = appendLog(it.activityLog, "DNSTT completed"),
            )
        }
    }

    fun markDnsttFailed(message: String) {
        _state.update {
            it.copy(
                dnsttSessionStatus = SessionStatus.FAILED,
                dnsttLastError = message,
                activityLog = appendLog(it.activityLog, "DNSTT failed: $message"),
            )
        }
    }

    fun markDnsttCancelled() {
        _state.update {
            it.copy(
                dnsttSessionStatus = SessionStatus.CANCELLED,
                activityLog = appendLog(it.activityLog, "DNSTT cancelled"),
            )
        }
    }

    fun addWarning(message: String) {
        _state.update {
            it.copy(
                activityLog = appendLog(it.activityLog, message),
            )
        }
    }

    fun markTransparentProxyDetected() {
        _state.update {
            it.copy(
                transparentProxyDetected = true,
                activityLog = appendLog(
                    it.activityLog,
                    "Transparent DNS proxy detected; scan results may be inaccurate",
                ),
            )
        }
    }

    fun markScanCompleted() {
        _state.update {
            it.copy(
                sessionStatus = SessionStatus.COMPLETED,
                activityLog = appendLog(it.activityLog, "Scan completed"),
            )
        }
    }

    fun markScanFailed(message: String) {
        _state.update {
            it.copy(
                sessionStatus = SessionStatus.FAILED,
                lastError = message,
                activityLog = appendLog(it.activityLog, "Scan failed: $message"),
            )
        }
    }

    fun markScanCancelled() {
        _state.update {
            it.copy(
                sessionStatus = SessionStatus.CANCELLED,
                activityLog = appendLog(it.activityLog, "Scan cancelled"),
            )
        }
    }

    private fun applyParseResult(result: TargetParseResult) {
        _state.update { current ->
            val status = when {
                result.entries.isEmpty() -> SessionStatus.IDLE
                current.sessionStatus == SessionStatus.RUNNING -> SessionStatus.RUNNING
                else -> SessionStatus.READY
            }

            current.copy(
                parsedTargets = result.entries,
                parseWarnings = result.warnings,
                totalAddresses = result.totalAddresses,
                totalScanHosts = result.totalScanHosts,
                sessionStatus = status,
                dnsttSessionStatus = SessionStatus.IDLE,
                dnsttProgress = DnsttProgress(),
                dnsttResolvers = emptyList(),
                dnsttResolverVisibleLimit = initialResultPreviewLimit,
                dnsttResolverCount = 0,
                dnsttFailures = emptyList(),
                dnsttFailureVisibleLimit = initialResultPreviewLimit,
                dnsttFailureCount = 0,
                lastError = result.errorMessage,
                dnsttLastError = null,
                targetsDirty = false,
                activityLog = appendLog(
                    current.activityLog,
                    if (result.entries.isEmpty()) {
                        result.errorMessage ?: "Target parsing produced no entries"
                    } else {
                        "Loaded ${result.entries.size} target range(s) for ${result.totalScanHosts} scan hosts"
                    },
                ),
            )
        }
    }

    private fun updateDraft(transform: ScanConfigDraft.() -> ScanConfigDraft) {
        _state.update { it.copy(configDraft = it.configDraft.transform()) }
    }

    private fun updateDnsttDraft(transform: DnsttConfigDraft.() -> DnsttConfigDraft) {
        _state.update { it.copy(dnsttConfigDraft = it.dnsttConfigDraft.transform()) }
    }

    private fun sanitizeScanDraft(draft: ScanConfigDraft): ScanConfigDraft {
        return draft.copy(
            workers = sanitizeIntegerInput(draft.workers, minValue = 1, maxValue = maxDnsScanWorkers),
            timeoutMillis = sanitizeIntegerInput(
                value = draft.timeoutMillis,
                minValue = minDnsTimeoutMillis,
                maxValue = maxDnsTimeoutMillis,
            ),
            port = sanitizeIntegerInput(draft.port, minValue = 1, maxValue = 65_535),
            querySize = sanitizeNonNegativeIntInput(draft.querySize),
            scoreThreshold = sanitizeIntegerInput(draft.scoreThreshold, minValue = 1, maxValue = 6),
        )
    }

    private fun sanitizeIntegerInput(
        value: String,
        minValue: Int,
        maxValue: Int? = null,
    ): String {
        val digits = integerPart(value)
        val parsed = digits.toIntOrNull() ?: return digits
        val clamped = maxValue?.let { parsed.coerceIn(minValue, it) } ?: parsed.coerceAtLeast(minValue)
        return clamped.toString()
    }

    private fun sanitizeNonNegativeIntInput(value: String): String {
        val digits = integerPart(value)
        val parsed = digits.toIntOrNull() ?: return digits
        return parsed.coerceAtLeast(0).toString()
    }

    private fun integerPart(value: String): String {
        return value.trim()
            .substringBefore('.')
            .filter { it.isDigit() }
    }

    private fun appendLog(existing: List<String>, message: String): List<String> {
        val timestamp = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"))
        return (existing + "[$timestamp] $message").takeLast(20)
    }

    private fun buildResolverPreviewLocked(
        sort: SuccessSortOption,
        limit: Int,
    ): List<ResolverRecord> {
        return resolverRecords
            .sortedWith(comparatorFor(sort))
            .take(limit)
    }

    private fun buildDnsttResultPreviewsLocked(
        sort: DnsttSortOption,
        e2eRequested: Boolean,
        successLimit: Int,
        failureLimit: Int,
    ): DnsttResultPreviews {
        return DnsttResultPreviews(
            successes = buildDnsttSuccessPreviewLocked(sort, e2eRequested, successLimit),
            successCount = countDnsttSuccessesLocked(e2eRequested).toLong(),
            failures = buildDnsttFailurePreviewLocked(sort, e2eRequested, failureLimit),
            failureCount = countDnsttFailuresLocked(e2eRequested).toLong(),
        )
    }

    private fun buildDnsttSuccessPreviewLocked(
        sort: DnsttSortOption,
        e2eRequested: Boolean,
        limit: Int,
    ): List<ResolverRecord> {
        return dnsttResolverRecords
            .filter { resolver -> resolver.isSuccessfulDnstt(e2eRequested) }
            .sortedWith(dnsttComparatorFor(sort))
            .take(limit)
    }

    private fun buildDnsttFailurePreviewLocked(
        sort: DnsttSortOption,
        e2eRequested: Boolean,
        limit: Int,
    ): List<ResolverRecord> {
        return dnsttResolverRecords
            .filter { resolver -> resolver.dnsttChecked && !resolver.isSuccessfulDnstt(e2eRequested) }
            .sortedWith(dnsttComparatorFor(sort))
            .take(limit)
    }

    private fun countDnsttSuccessesLocked(e2eRequested: Boolean): Int {
        return dnsttResolverRecords.count { resolver -> resolver.isSuccessfulDnstt(e2eRequested) }
    }

    private fun countDnsttFailuresLocked(e2eRequested: Boolean): Int {
        return dnsttResolverRecords.count { resolver ->
            resolver.dnsttChecked && !resolver.isSuccessfulDnstt(e2eRequested)
        }
    }

    private fun mergeResolverPreview(
        currentPreview: List<ResolverRecord>,
        additions: Collection<ResolverRecord>,
        comparator: Comparator<ResolverRecord>,
        limit: Int,
    ): List<ResolverRecord> {
        return (currentPreview + additions)
            .sortedWith(comparator)
            .take(limit)
    }

    private fun nextVisibleLimit(
        currentLimit: Int,
        totalCount: Int,
    ): Int {
        if (totalCount <= currentLimit) {
            return currentLimit
        }
        return minOf(currentLimit + resultLoadMorePageSize, totalCount)
    }

    private fun comparatorFor(sort: SuccessSortOption): Comparator<ResolverRecord> {
        return when (sort) {
            SuccessSortOption.DNS_SCORE -> scanResolverComparator
            SuccessSortOption.TUNNEL_SPEED -> tunnelSpeedComparator
            SuccessSortOption.E2E_SPEED -> e2eSpeedComparator
        }
    }

    private fun dnsttComparatorFor(sort: DnsttSortOption): Comparator<ResolverRecord> {
        return when (sort) {
            DnsttSortOption.TUNNEL_SPEED -> dnsttTunnelSpeedComparator
            DnsttSortOption.E2E_SPEED -> dnsttE2eSpeedComparator
        }
    }

    private fun matchesResolver(
        left: ResolverRecord,
        right: ResolverRecord,
    ): Boolean {
        return left.ip == right.ip &&
            left.prefix == right.prefix &&
            left.transport == right.transport
    }

    private fun ResolverRecord.isSuccessfulDnstt(e2eRequested: Boolean): Boolean {
        return if (e2eRequested) {
            dnsttE2eOk
        } else {
            dnsttTunnelOk
        }
    }

    private companion object {
        const val initialResultPreviewLimit = 10
        const val resultPreviewLimit = initialResultPreviewLimit
        const val resultLoadMorePageSize = 50

        val scanResolverComparator =
            compareByDescending<ResolverRecord> { record -> record.tunnelScore }
                .thenBy { record -> latencySortKey(record.latencyMillis) }
                .thenBy { record -> record.ip }
                .thenBy { record -> record.prefix }

        val tunnelSpeedComparator =
            compareByDescending<ResolverRecord> { record -> record.dnsttTunnelOk }
                .thenBy { record -> latencySortKey(record.dnsttTunnelMillis) }
                .thenByDescending { record -> record.dnsttChecked }
                .thenByDescending { record -> record.tunnelScore }
                .thenBy { record -> latencySortKey(record.latencyMillis) }
                .thenBy { record -> record.ip }
                .thenBy { record -> record.prefix }

        val e2eSpeedComparator =
            compareByDescending<ResolverRecord> { record -> record.dnsttE2eOk }
                .thenBy { record -> latencySortKey(record.dnsttE2eMillis) }
                .thenByDescending { record -> record.dnsttTunnelOk }
                .thenBy { record -> latencySortKey(record.dnsttTunnelMillis) }
                .thenByDescending { record -> record.dnsttChecked }
                .thenByDescending { record -> record.tunnelScore }
                .thenBy { record -> latencySortKey(record.latencyMillis) }
                .thenBy { record -> record.ip }
                .thenBy { record -> record.prefix }

        val dnsttTunnelSpeedComparator =
            compareByDescending<ResolverRecord> { record -> record.dnsttTunnelOk }
                .thenBy { record -> latencySortKey(record.dnsttTunnelMillis) }
                .thenByDescending { record -> record.dnsttE2eOk }
                .thenBy { record -> latencySortKey(record.dnsttE2eMillis) }
                .thenByDescending { record -> record.tunnelScore }
                .thenBy { record -> record.ip }
                .thenBy { record -> record.prefix }

        val dnsttE2eSpeedComparator =
            compareByDescending<ResolverRecord> { record -> record.dnsttE2eOk }
                .thenBy { record -> latencySortKey(record.dnsttE2eMillis) }
                .thenByDescending { record -> record.dnsttTunnelOk }
                .thenBy { record -> latencySortKey(record.dnsttTunnelMillis) }
                .thenByDescending { record -> record.tunnelScore }
                .thenBy { record -> record.ip }
                .thenBy { record -> record.prefix }

        fun latencySortKey(value: Long): Long = if (value > 0) value else Long.MAX_VALUE
    }
}
