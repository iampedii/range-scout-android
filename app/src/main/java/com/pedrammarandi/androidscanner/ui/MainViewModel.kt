package com.pedrammarandi.androidscanner.ui

import androidx.lifecycle.ViewModel
import com.pedrammarandi.androidscanner.scan.model.DnsttSortOption
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import com.pedrammarandi.androidscanner.scan.runtime.ScanController
import com.pedrammarandi.androidscanner.scan.runtime.ScanRepository
import com.pedrammarandi.androidscanner.scan.runtime.WhiteDnsListOption
import com.pedrammarandi.androidscanner.scan.model.SuccessSortOption
import kotlinx.coroutines.flow.StateFlow

class MainViewModel(
    private val repository: ScanRepository,
    private val controller: ScanController,
) : ViewModel() {
    val state: StateFlow<com.pedrammarandi.androidscanner.scan.model.ScannerUiState> = repository.state

    fun updateTargetInput(value: String) = repository.updateTargetInput(value)

    fun importWhiteDnsList(option: WhiteDnsListOption) = repository.importWhiteDnsList(option)

    fun updateWorkers(value: String) = repository.updateWorkers(value)

    fun updateTimeoutMillis(value: String) = repository.updateTimeoutMillis(value)

    fun updatePort(value: String) = repository.updatePort(value)

    fun updateProbeDomain(value: String) = repository.updateProbeDomain(value)

    fun updateScoreThreshold(value: String) = repository.updateScoreThreshold(value)

    fun updateProtocol(value: ScanTransport) = repository.updateProtocol(value)

    fun updateSuccessSort(value: SuccessSortOption) = repository.updateSuccessSort(value)

    fun updateDnsttSort(value: DnsttSortOption) = repository.updateDnsttSort(value)

    fun updateDnsttWorkers(value: String) = repository.updateDnsttWorkers(value)

    fun updateDnsttTimeoutMillis(value: String) = repository.updateDnsttTimeoutMillis(value)

    fun updateDnsttTransport(value: DnsttTransport) = repository.updateDnsttTransport(value)

    fun updateDnsttDomain(value: String) = repository.updateDnsttDomain(value)

    fun updateDnsttPubkey(value: String) = repository.updateDnsttPubkey(value)

    fun updateDnsttE2eTimeoutSeconds(value: String) = repository.updateDnsttE2eTimeoutSeconds(value)

    fun updateDnsttE2eUrl(value: String) = repository.updateDnsttE2eUrl(value)

    fun updateDnsttSocksUsername(value: String) = repository.updateDnsttSocksUsername(value)

    fun updateDnsttSocksPassword(value: String) = repository.updateDnsttSocksPassword(value)

    fun toggleDnsttNearbyIps() = repository.toggleDnsttNearbyIps()

    fun toggleAdvancedConfig() = repository.toggleAdvancedConfig()

    fun showSetupPage() = repository.showSetupPage()

    fun showScanPage() = repository.showScanPage()

    fun loadTargets() {
        repository.loadTargets()
    }

    fun saveProfile(): Result<Unit> = repository.saveProfile()

    fun allResolvers(): List<ResolverRecord> = repository.snapshotResolvers()

    fun allFailures(): List<FailureRecord> = repository.snapshotFailures()

    fun allDnsttResolvers(): List<ResolverRecord> = repository.snapshotDnsttResolvers()

    fun loadMoreResolvers() = repository.loadMoreResolvers()

    fun loadMoreFailures() = repository.loadMoreFailures()

    fun loadMoreDnsttResolvers() = repository.loadMoreDnsttResolvers()

    fun loadMoreDnsttFailures() = repository.loadMoreDnsttFailures()

    fun startScan() {
        if ((state.value.targetsDirty || state.value.parsedTargets.isEmpty()) && !repository.loadTargets()) {
            return
        }
        if (repository.buildRuntimeRequest().isSuccess) {
            repository.showScanPage()
            controller.start()
        }
    }

    fun cancelScan() {
        controller.cancel()
    }

    fun startDnstt() {
        if (repository.buildDnsttRuntimeRequest().isSuccess) {
            controller.startDnstt()
        }
    }

    fun cancelDnstt() {
        controller.cancel()
    }
}
