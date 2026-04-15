package com.pedrammarandi.androidscanner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.pedrammarandi.androidscanner.ui.MainViewModel
import com.pedrammarandi.androidscanner.ui.ScannerScreen
import com.pedrammarandi.androidscanner.ui.theme.AndroidScannerTheme

class MainActivity : ComponentActivity() {
    private val viewModel by viewModels<MainViewModel> {
        val app = application as AndroidScannerApplication
        viewModelFactory {
            initializer {
                MainViewModel(
                    repository = app.container.scanRepository,
                    controller = app.container.scanController,
                )
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )

        setContent {
            AndroidScannerTheme {
                val state by viewModel.state.collectAsStateWithLifecycle()
                ScannerScreen(
                    state = state,
                    onSaveProfile = viewModel::saveProfile,
                    onTargetInputChanged = viewModel::updateTargetInput,
                    onImportWhiteDnsList = viewModel::importWhiteDnsList,
                    onLoadTargets = viewModel::loadTargets,
                    onWorkersChanged = viewModel::updateWorkers,
                    onTimeoutChanged = viewModel::updateTimeoutMillis,
                    onPortChanged = viewModel::updatePort,
                    onProbeDomainChanged = viewModel::updateProbeDomain,
                    onScoreThresholdChanged = viewModel::updateScoreThreshold,
                    onProtocolSelected = viewModel::updateProtocol,
                    onSuccessSortChanged = viewModel::updateSuccessSort,
                    onDnsttSortChanged = viewModel::updateDnsttSort,
                    onDnsttWorkersChanged = viewModel::updateDnsttWorkers,
                    onDnsttTimeoutChanged = viewModel::updateDnsttTimeoutMillis,
                    onDnsttTransportSelected = viewModel::updateDnsttTransport,
                    onDnsttDomainChanged = viewModel::updateDnsttDomain,
                    onDnsttPubkeyChanged = viewModel::updateDnsttPubkey,
                    onDnsttE2eTimeoutChanged = viewModel::updateDnsttE2eTimeoutSeconds,
                    onDnsttE2eUrlChanged = viewModel::updateDnsttE2eUrl,
                    onDnsttSocksUsernameChanged = viewModel::updateDnsttSocksUsername,
                    onDnsttSocksPasswordChanged = viewModel::updateDnsttSocksPassword,
                    onToggleDnsttNearbyIps = viewModel::toggleDnsttNearbyIps,
                    loadAllResolvers = viewModel::allResolvers,
                    loadAllFailures = viewModel::allFailures,
                    loadAllDnsttResolvers = viewModel::allDnsttResolvers,
                    onLoadMoreSuccess = viewModel::loadMoreResolvers,
                    onLoadMoreFailures = viewModel::loadMoreFailures,
                    onLoadMoreDnstt = viewModel::loadMoreDnsttResolvers,
                    onLoadMoreDnsttFailures = viewModel::loadMoreDnsttFailures,
                    onStartScan = viewModel::startScan,
                    onCancelScan = viewModel::cancelScan,
                    onStartDnstt = viewModel::startDnstt,
                    onCancelDnstt = viewModel::cancelDnstt,
                )
            }
        }
    }
}
