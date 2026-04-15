package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.input.TargetParser
import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.model.PrefixEntry
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanConfig
import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft
import com.pedrammarandi.androidscanner.scan.model.ScannerPage
import com.pedrammarandi.androidscanner.scan.model.ScanRuntimeRequest
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import com.pedrammarandi.androidscanner.scan.model.DnsttSortOption
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.SuccessSortOption
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanRepositoryTest {
    @Test
    fun appendResolverSortsByScoreThenLatencyThenIp() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.20",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                latencyMillis = 30,
                tunnelScore = 2,
            ),
        )
        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.10",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                latencyMillis = 40,
                tunnelScore = 4,
            ),
        )
        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.11",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                latencyMillis = 20,
                tunnelScore = 4,
            ),
        )

        assertEquals(
            listOf("198.51.100.11", "198.51.100.10", "198.51.100.20"),
            repository.state.value.resolvers.map { it.ip },
        )
    }

    @Test
    fun markScanRunningSwitchesToScanPageAndClearsPreviousResults() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.showScanPage()
        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.10",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
            ),
        )
        repository.appendFailure(
            FailureRecord(
                ip = "198.51.100.11",
                prefix = "198.51.100.0/24",
                reason = "No DNS response",
            ),
        )

        repository.markScanRunning(
            ScanRuntimeRequest(
                config = ScanConfig(
                    workers = 32,
                    timeoutMillis = 15000,
                    port = 53,
                    protocol = ScanTransport.UDP,
                    probeDomain = "github.com",
                    querySize = 100,
                    scoreThreshold = 2,
                ),
                targets = listOf(
                    PrefixEntry(
                        prefix = "198.51.100.0/24",
                        sourceLabel = "manual",
                        sourceAsns = emptyList(),
                        totalAddresses = 256,
                        scanHosts = 254,
                    ),
                ),
                totalTargets = 254,
            ),
        )

        assertEquals(ScannerPage.SCAN, repository.state.value.currentPage)
        assertEquals(emptyList<ResolverRecord>(), repository.state.value.resolvers)
        assertEquals(emptyList<FailureRecord>(), repository.state.value.failures)
    }

    @Test
    fun appendFailurePreservesFailureOrder() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendFailure(
            FailureRecord(
                ip = "198.51.100.20",
                prefix = "198.51.100.0/24",
                reason = "No DNS response over UDP",
            ),
        )
        repository.appendFailure(
            FailureRecord(
                ip = "198.51.100.21",
                prefix = "198.51.100.0/24",
                reason = "No DNS response over UDP",
            ),
        )

        assertEquals(
            listOf("198.51.100.20", "198.51.100.21"),
            repository.state.value.failures.map { it.ip },
        )
    }

    @Test
    fun appendResolversMergesBatchesAndKeepsSortOrder() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendResolvers(
            listOf(
                ResolverRecord(
                    ip = "198.51.100.20",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    latencyMillis = 30,
                    tunnelScore = 2,
                ),
                ResolverRecord(
                    ip = "198.51.100.30",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    latencyMillis = 50,
                    tunnelScore = 4,
                ),
            ),
        )
        repository.appendResolvers(
            listOf(
                ResolverRecord(
                    ip = "198.51.100.10",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    latencyMillis = 20,
                    tunnelScore = 4,
                ),
            ),
        )

        assertEquals(
            listOf("198.51.100.10", "198.51.100.30", "198.51.100.20"),
            repository.state.value.resolvers.map { it.ip },
        )
        assertEquals(3L, repository.state.value.resolverCount)
    }

    @Test
    fun appendFailuresPreservesBatchOrder() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendFailures(
            listOf(
                FailureRecord(
                    ip = "198.51.100.20",
                    prefix = "198.51.100.0/24",
                    reason = "No DNS response over UDP",
                ),
                FailureRecord(
                    ip = "198.51.100.21",
                    prefix = "198.51.100.0/24",
                    reason = "No DNS response over UDP",
                ),
            ),
        )

        assertEquals(
            listOf("198.51.100.20", "198.51.100.21"),
            repository.state.value.failures.map { it.ip },
        )
        assertEquals(2L, repository.state.value.failureCount)
    }

    @Test
    fun loadMoreFailuresExpandsFailurePreview() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendFailures(
            (1..12).map { index ->
                FailureRecord(
                    ip = "198.51.100.$index",
                    prefix = "198.51.100.0/24",
                    reason = "No DNS response",
                )
            },
        )

        assertEquals(10, repository.state.value.failures.size)

        repository.loadMoreFailures()

        assertEquals(12, repository.state.value.failures.size)
        assertEquals(12L, repository.state.value.failureCount)
    }

    @Test
    fun uiStateCapsResolverPreviewButRuntimeSnapshotKeepsFullSet() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendResolvers(
            (1..12).map { index ->
                ResolverRecord(
                    ip = "198.51.100.$index",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = index,
                )
            },
        )

        assertEquals(10, repository.state.value.resolvers.size)
        assertEquals(12L, repository.state.value.resolverCount)
        assertEquals(12, repository.snapshotResolvers().size)
    }

    @Test
    fun loadMoreResolversExpandsSuccessPreviewWithoutExport() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendResolvers(
            (1..12).map { index ->
                ResolverRecord(
                    ip = "198.51.100.$index",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = index,
                )
            },
        )

        repository.loadMoreResolvers()

        assertEquals(12, repository.state.value.resolvers.size)
        assertEquals(12L, repository.state.value.resolverCount)
    }

    @Test
    fun updateSuccessSortRecomputesPreviewUsingRequestedOrder() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.appendResolvers(
            listOf(
                ResolverRecord(
                    ip = "198.51.100.20",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = 4,
                    dnsttChecked = true,
                    dnsttTunnelOk = true,
                    dnsttTunnelMillis = 140,
                ),
                ResolverRecord(
                    ip = "198.51.100.10",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = 3,
                    dnsttChecked = true,
                    dnsttTunnelOk = true,
                    dnsttTunnelMillis = 80,
                ),
                ResolverRecord(
                    ip = "198.51.100.30",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = 6,
                ),
            ),
        )

        repository.updateSuccessSort(SuccessSortOption.TUNNEL_SPEED)

        assertEquals(
            listOf("198.51.100.10", "198.51.100.20", "198.51.100.30"),
            repository.state.value.resolvers.map { it.ip },
        )
    }

    @Test
    fun buildDnsttRuntimeRequestUsesQualifiedResolversAndPrefixes() {
        val repository = ScanRepository(targetParser = TargetParser())
        repository.updateTargetInput("198.51.100.0/24")
        repository.updateDnsttDomain("dnstt.example")
        assertTrue(repository.loadTargets())

        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.10",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 4,
                qualifiedForTunnel = true,
            ),
        )
        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.11",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 1,
                qualifiedForTunnel = false,
            ),
        )

        val request = repository.buildDnsttRuntimeRequest().getOrThrow()

        assertEquals("example.com", request.scanConfig.probeDomain)
        assertEquals("dnstt.example", request.dnsttConfig.domain)
        assertEquals(2, request.scanConfig.scoreThreshold)
        assertEquals(listOf("198.51.100.0/24"), request.basePrefixes)
        assertEquals(2, request.resolvers.size)
    }

    @Test
    fun buildDnsttRuntimeRequestFailsWithoutQualifiedResolvers() {
        val repository = ScanRepository(targetParser = TargetParser())
        repository.updateTargetInput("198.51.100.0/24")
        assertTrue(repository.loadTargets())
        repository.appendResolver(
            ResolverRecord(
                ip = "198.51.100.11",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 1,
                qualifiedForTunnel = false,
            ),
        )

        val result = repository.buildDnsttRuntimeRequest()

        assertTrue(result.isFailure)
        assertTrue(repository.state.value.dnsttLastError.orEmpty().contains("No score-qualified resolvers"))
    }

    @Test
    fun upsertDnsttResolverReplacesExistingEntry() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.20",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                dnsttChecked = true,
                dnsttTunnelOk = true,
                dnsttError = "",
            ),
        )
        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.20",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                dnsttChecked = true,
                dnsttTunnelOk = true,
                dnsttE2eOk = true,
                dnsttE2eMillis = 420,
            ),
        )

        assertEquals(1, repository.state.value.dnsttResolvers.size)
        assertTrue(repository.state.value.dnsttResolvers.first().dnsttE2eOk)
        assertFalse(repository.state.value.dnsttResolvers.first().dnsttNearby)
    }

    @Test
    fun loadMoreDnsttResolversExpandsDnsttPreviewWithoutExport() {
        val repository = ScanRepository(targetParser = TargetParser())

        (1..12).forEach { index ->
            repository.upsertDnsttResolver(
                ResolverRecord(
                    ip = "198.51.100.$index",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = index,
                    dnsttChecked = true,
                    dnsttTunnelOk = true,
                ),
            )
        }

        repository.loadMoreDnsttResolvers()

        assertEquals(12, repository.state.value.dnsttResolvers.size)
        assertEquals(12L, repository.state.value.dnsttResolverCount)
    }

    @Test
    fun upsertDnsttResolverSeparatesSuccessesAndFailures() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.20",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                dnsttChecked = true,
                dnsttTunnelOk = true,
            ),
        )
        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.30",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                dnsttChecked = true,
                dnsttTunnelOk = false,
                dnsttError = "timeout",
            ),
        )

        assertEquals(listOf("198.51.100.20"), repository.state.value.dnsttResolvers.map { it.ip })
        assertEquals(1L, repository.state.value.dnsttResolverCount)
        assertEquals(listOf("198.51.100.30"), repository.state.value.dnsttFailures.map { it.ip })
        assertEquals(1L, repository.state.value.dnsttFailureCount)
    }

    @Test
    fun updateDnsttSortReordersDnsttResultsBySelectedSpeed() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.20",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 4,
                dnsttChecked = true,
                dnsttTunnelOk = true,
                dnsttE2eOk = true,
                dnsttTunnelMillis = 60,
                dnsttE2eMillis = 260,
            ),
        )
        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.10",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 4,
                dnsttChecked = true,
                dnsttTunnelOk = true,
                dnsttE2eOk = true,
                dnsttTunnelMillis = 120,
                dnsttE2eMillis = 180,
            ),
        )

        repository.updateDnsttSort(DnsttSortOption.TUNNEL_SPEED)
        assertEquals("198.51.100.20", repository.state.value.dnsttResolvers.first().ip)

        repository.updateDnsttSort(DnsttSortOption.E2E_SPEED)
        assertEquals("198.51.100.10", repository.state.value.dnsttResolvers.first().ip)
    }

    @Test
    fun upsertDnsttResolverUpdatesMatchingBaseResolverForSuccessSorts() {
        val repository = ScanRepository(targetParser = TargetParser())
        repository.updateSuccessSort(SuccessSortOption.E2E_SPEED)

        repository.appendResolvers(
            listOf(
                ResolverRecord(
                    ip = "198.51.100.20",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = 4,
                ),
                ResolverRecord(
                    ip = "198.51.100.30",
                    transport = ScanTransport.UDP,
                    prefix = "198.51.100.0/24",
                    dnsReachable = true,
                    scanStatus = "WORKING",
                    tunnelScore = 4,
                ),
            ),
        )

        repository.upsertDnsttResolver(
            ResolverRecord(
                ip = "198.51.100.30",
                transport = ScanTransport.UDP,
                prefix = "198.51.100.0/24",
                dnsReachable = true,
                scanStatus = "WORKING",
                tunnelScore = 4,
                dnsttChecked = true,
                dnsttTunnelOk = true,
                dnsttE2eOk = true,
                dnsttTunnelMillis = 90,
                dnsttE2eMillis = 180,
            ),
        )

        assertEquals("198.51.100.30", repository.state.value.resolvers.first().ip)
        assertEquals(180L, repository.state.value.resolvers.first().dnsttE2eMillis)
    }

    @Test
    fun saveProfilePersistsCurrentScanAndDnsttDrafts() {
        val profileStore = FakeScanProfileStore()
        val repository = ScanRepository(
            targetParser = TargetParser(),
            profileStore = profileStore,
        )

        repository.updateWorkers("128")
        repository.updateProbeDomain("example.com")
        repository.updateDnsttTransport(DnsttTransport.TCP)
        repository.updateDnsttDomain("tunnel.example")
        repository.updateDnsttPubkey("deadbeef")

        val result = repository.saveProfile()

        assertTrue(result.isSuccess)
        assertEquals("8", profileStore.savedProfile?.scanConfigDraft?.workers)
        assertEquals("example.com", profileStore.savedProfile?.scanConfigDraft?.probeDomain)
        assertEquals(DnsttTransport.TCP, profileStore.savedProfile?.dnsttConfigDraft?.transport)
        assertEquals("tunnel.example", profileStore.savedProfile?.dnsttConfigDraft?.domain)
        assertEquals("deadbeef", profileStore.savedProfile?.dnsttConfigDraft?.pubkey)
    }

    @Test
    fun updateScanNumericFieldsReflectRuntimeLimits() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.updateWorkers("16")
        repository.updateTimeoutMillis("50.00")
        repository.updatePort("70000")
        repository.updateScoreThreshold("9")

        assertEquals("8", repository.state.value.configDraft.workers)
        assertEquals("500", repository.state.value.configDraft.timeoutMillis)
        assertEquals("65535", repository.state.value.configDraft.port)
        assertEquals("6", repository.state.value.configDraft.scoreThreshold)
    }

    @Test
    fun importWhiteDnsListPopulatesTargetsAndSelectsProtocol() {
        val repository = ScanRepository(targetParser = TargetParser())

        repository.importWhiteDnsList(WhiteDnsListOption.UDP)

        assertEquals(ScanTransport.UDP, repository.state.value.configDraft.protocol)
        assertTrue(repository.state.value.targetsDirty)
        assertTrue(repository.state.value.targetInput.startsWith("185.212.51.144"))
        assertTrue(repository.state.value.targetInput.contains("185.49.86.202"))

        repository.importWhiteDnsList(WhiteDnsListOption.TCP)

        assertEquals(ScanTransport.TCP, repository.state.value.configDraft.protocol)
        assertTrue(repository.state.value.targetInput.startsWith("85.185.105.104"))
        assertTrue(repository.state.value.targetInput.contains("2.189.1.1"))
        assertFalse(repository.state.value.targetInput.startsWith("185.212.51.144"))
    }

    @Test
    fun repositoryLoadsSavedProfileWithoutRestoringImportedTargets() {
        val repository = ScanRepository(
            targetParser = TargetParser(),
            profileStore = FakeScanProfileStore(
                initialProfile = ScannerProfile(
                    scanConfigDraft = ScanConfigDraft(
                        workers = "96",
                        probeDomain = "saved.example",
                    ),
                    dnsttConfigDraft = DnsttConfigDraft(
                        transport = DnsttTransport.TCP,
                        domain = "dnstt.saved.example",
                    ),
                ),
            ),
        )

        assertEquals("8", repository.state.value.configDraft.workers)
        assertEquals("saved.example", repository.state.value.configDraft.probeDomain)
        assertEquals(DnsttTransport.TCP, repository.state.value.dnsttConfigDraft.transport)
        assertEquals("dnstt.saved.example", repository.state.value.dnsttConfigDraft.domain)
        assertEquals("", repository.state.value.targetInput)
        assertTrue(repository.state.value.parsedTargets.isEmpty())
        assertNull(repository.state.value.lastError)
    }
}

private class FakeScanProfileStore(
    private val initialProfile: ScannerProfile? = null,
) : ScanProfileStore {
    var savedProfile: ScannerProfile? = null

    override fun load(): ScannerProfile? = initialProfile

    override fun save(profile: ScannerProfile) {
        savedProfile = profile
    }
}
