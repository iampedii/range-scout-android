package com.pedrammarandi.androidscanner.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pedrammarandi.androidscanner.scan.model.DnsttSortOption
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.model.PrefixEntry
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanTransport
import com.pedrammarandi.androidscanner.scan.model.ScannerUiState
import com.pedrammarandi.androidscanner.scan.model.SessionStatus
import com.pedrammarandi.androidscanner.scan.model.SuccessSortOption
import com.pedrammarandi.androidscanner.scan.input.TargetInputNormalizer
import com.pedrammarandi.androidscanner.scan.runtime.WhiteDnsListOption
import com.pedrammarandi.androidscanner.ui.theme.*
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class ExportPayload(
    val fileName: String,
    val content: String,
)

private data class SortChipOption<T>(
    val value: T,
    val label: String,
    val color: Color,
)

private data class ResultMetric(
    val label: String,
    val value: String,
    val color: Color,
)

private data class ResultBadge(
    val label: String,
    val color: Color,
)

@OptIn(ExperimentalLayoutApi::class, androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen(
    state: ScannerUiState,
    onSaveProfile: () -> Result<Unit>,
    onTargetInputChanged: (String) -> Unit,
    onImportWhiteDnsList: (WhiteDnsListOption) -> Unit,
    onLoadTargets: () -> Unit,
    onWorkersChanged: (String) -> Unit,
    onTimeoutChanged: (String) -> Unit,
    onPortChanged: (String) -> Unit,
    onProbeDomainChanged: (String) -> Unit,
    onScoreThresholdChanged: (String) -> Unit,
    onProtocolSelected: (ScanTransport) -> Unit,
    onSuccessSortChanged: (SuccessSortOption) -> Unit,
    onDnsttSortChanged: (DnsttSortOption) -> Unit,
    onDnsttWorkersChanged: (String) -> Unit,
    onDnsttTimeoutChanged: (String) -> Unit,
    onDnsttTransportSelected: (DnsttTransport) -> Unit,
    onDnsttDomainChanged: (String) -> Unit,
    onDnsttPubkeyChanged: (String) -> Unit,
    onDnsttE2eTimeoutChanged: (String) -> Unit,
    onDnsttE2eUrlChanged: (String) -> Unit,
    onDnsttSocksUsernameChanged: (String) -> Unit,
    onDnsttSocksPasswordChanged: (String) -> Unit,
    onToggleDnsttNearbyIps: () -> Unit,
    loadAllResolvers: () -> List<ResolverRecord>,
    loadAllFailures: () -> List<FailureRecord>,
    loadAllDnsttResolvers: () -> List<ResolverRecord>,
    onLoadMoreSuccess: () -> Unit,
    onLoadMoreFailures: () -> Unit,
    onLoadMoreDnstt: () -> Unit,
    onLoadMoreDnsttFailures: () -> Unit,
    onStartScan: () -> Unit,
    onCancelScan: () -> Unit,
    onStartDnstt: () -> Unit,
    onCancelDnstt: () -> Unit,
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val progressFraction = if (state.progress.total > 0) {
        (state.progress.scanned.toFloat() / state.progress.total.toFloat()).coerceIn(0f, 1f)
    } else {
        0f
    }
    var pendingExport by remember { mutableStateOf<ExportPayload?>(null) }
    var selectedTab by remember { mutableStateOf(0) }
    var scanResultsFilter by remember { mutableStateOf("all") }
    var importInProgress by remember { mutableStateOf(false) }
    val importScope = rememberCoroutineScope()

    val importTargetsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) {
            return@rememberLauncherForActivityResult
        }

        if (importInProgress) {
            Toast.makeText(context, "Import already in progress", Toast.LENGTH_SHORT).show()
            return@rememberLauncherForActivityResult
        }

        importScope.launch {
            importInProgress = true
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val stream = context.contentResolver.openInputStream(uri)
                        ?: error("Unable to open import file.")
                    stream.bufferedReader().use { reader ->
                        TargetInputNormalizer.normalizeImportedTargets(reader)
                    }
                }
            }

            importInProgress = false
            val importedTargets = result.getOrNull()
            if (result.isFailure || importedTargets == null || importedTargets.text.isBlank()) {
                val message = result.exceptionOrNull()?.message ?: "No targets found in import file"
                Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                return@launch
            }

            onTargetInputChanged(importedTargets.text)
            Toast.makeText(
                context,
                "Imported ${importedTargets.targetCount} target(s)",
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val payload = pendingExport
        pendingExport = null
        if (payload == null || uri == null) {
            return@rememberLauncherForActivityResult
        }

        val result = runCatching {
            val stream = context.contentResolver.openOutputStream(uri)
                ?: error("Unable to open export destination.")
            stream.bufferedWriter().use { writer ->
                writer.write(payload.content)
            }
        }

        if (result.isSuccess) {
            Toast.makeText(context, "Export saved", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(context, "Export failed", Toast.LENGTH_SHORT).show()
        }
    }

    fun copyToClipboard(label: String, content: String, emptyMessage: String) {
        if (content.isBlank()) {
            Toast.makeText(context, emptyMessage, Toast.LENGTH_SHORT).show()
            return
        }
        clipboardManager.setText(AnnotatedString(content))
        Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
    }

    fun copySingleIp(ip: String, label: String) {
        clipboardManager.setText(AnnotatedString(ip))
        Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
    }

    fun exportDocument(
        prefix: String,
        content: String,
        emptyMessage: String,
        extension: String = "txt",
    ) {
        if (content.isBlank()) {
            Toast.makeText(context, emptyMessage, Toast.LENGTH_SHORT).show()
            return
        }
        val payload = ExportPayload(
            fileName = exportFileName(prefix, extension),
            content = content,
        )
        pendingExport = payload
        exportLauncher.launch(payload.fileName)
    }

    fun saveProfile() {
        val result = onSaveProfile()
        if (result.isSuccess) {
            Toast.makeText(context, "Profile saved", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(
                context,
                result.exceptionOrNull()?.message ?: "Profile save failed",
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace)
    ) {
        Scaffold(
            containerColor = Color.Transparent,
            topBar = {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .background(NeonBlue, CircleShape)
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "Range Scout",
                                    style = MaterialTheme.typography.headlineSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = TextPrimary,
                                )
                                Text(
                                    text = "v0.1",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Light,
                                    color = TextTertiary,
                                )
                            }
                        }
                    },
                    actions = {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .background(NeonBlue.copy(alpha = 0.15f))
                                .border(1.dp, NeonBlue, RoundedCornerShape(10.dp))
                                .clickable(onClick = ::saveProfile)
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                        ) {
                            Text(
                                text = "Save Profile",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = NeonBlue,
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = DarkSurface,
                        titleContentColor = TextPrimary,
                    ),
                )
            },
        ) { innerPadding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                TabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = DarkSurface,
                    contentColor = NeonBlue,
                    indicator = { tabPositions ->
                        if (selectedTab < tabPositions.size) {
                            Box(
                                modifier = Modifier
                                    .tabIndicatorOffset(tabPositions[selectedTab])
                                    .height(3.dp)
                                    .background(NeonBlue)
                            )
                        }
                    },
                    divider = { HorizontalDivider(color = BorderGlow) }
                ) {
                    Tab(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        text = {
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    "Scan DNS",
                                    fontWeight = if (selectedTab == 0) FontWeight.Bold else FontWeight.Normal,
                                    color = if (selectedTab == 0) NeonBlue else TextTertiary,
                                )
                                if (state.resolverCount > 0 || state.failureCount > 0) {
                                    Box(
                                        modifier = Modifier
                                            .background(NeonBlue, CircleShape)
                                            .padding(horizontal = 8.dp, vertical = 2.dp),
                                    ) {
                                        Text(
                                            "${state.resolverCount + state.failureCount}",
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = PrimaryForeground,
                                        )
                                    }
                                }
                            }
                        },
                    )
                    Tab(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        text = {
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    "DNSTT E2E",
                                    fontWeight = if (selectedTab == 1) FontWeight.Bold else FontWeight.Normal,
                                    color = if (selectedTab == 1) NeonBlue else TextTertiary,
                                )
                                if (state.dnsttProgress.checked > 0) {
                                    Box(
                                        modifier = Modifier
                                            .background(NeonBlue, CircleShape)
                                            .padding(horizontal = 8.dp, vertical = 2.dp),
                                    ) {
                                        Text(
                                            state.dnsttProgress.checked.toString(),
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = PrimaryForeground,
                                        )
                                    }
                                }
                            }
                        },
                    )
                }

                when (selectedTab) {
                    0 -> ModernScanTab(
                        state = state,
                        progressFraction = progressFraction,
                        importInProgress = importInProgress,
                        onTargetInputChanged = onTargetInputChanged,
                        onImportWhiteDnsList = onImportWhiteDnsList,
                        onImportTargetsFile = {
                            importTargetsLauncher.launch(
                                arrayOf(
                                    "text/plain",
                                    "text/*",
                                    "text/csv",
                                    "application/csv",
                                    "application/octet-stream",
                                ),
                            )
                        },
                        onLoadTargets = onLoadTargets,
                        onWorkersChanged = onWorkersChanged,
                        onTimeoutChanged = onTimeoutChanged,
                        onPortChanged = onPortChanged,
                        onProbeDomainChanged = onProbeDomainChanged,
                        onScoreThresholdChanged = onScoreThresholdChanged,
                        onProtocolSelected = onProtocolSelected,
                        successSort = state.successSort,
                        onSuccessSortChange = onSuccessSortChanged,
                        filter = scanResultsFilter,
                        onFilterChange = { scanResultsFilter = it },
                        onCopySuccess = {
                            copyToClipboard(
                                label = "IP addresses",
                                content = buildSuccessCopyText(loadAllResolvers()),
                                emptyMessage = "No successful results to copy.",
                            )
                        },
                        onExportSuccess = {
                            exportDocument(
                                prefix = "success",
                                content = buildSuccessExportText(loadAllResolvers()),
                                emptyMessage = "No successful results to export.",
                                extension = "csv",
                            )
                        },
                        onCopyFailures = {
                            copyToClipboard(
                                label = "IP addresses",
                                content = buildFailureCopyText(loadAllFailures()),
                                emptyMessage = "No failures to copy.",
                            )
                        },
                        onExportFailures = {
                            exportDocument(
                                prefix = "failures",
                                content = buildFailureExportText(loadAllFailures()),
                                emptyMessage = "No failures to export.",
                            )
                        },
                        onCopyFailureIp = { ip -> copySingleIp(ip, "Failed IP") },
                        onLoadMoreSuccess = onLoadMoreSuccess,
                        onLoadMoreFailures = onLoadMoreFailures,
                        onStartScan = onStartScan,
                        onCancelScan = onCancelScan,
                    )
                    1 -> ModernDnsttTab(
                        state = state,
                        onWorkersChanged = onDnsttWorkersChanged,
                        onTimeoutChanged = onDnsttTimeoutChanged,
                        onTransportSelected = onDnsttTransportSelected,
                        onDomainChanged = onDnsttDomainChanged,
                        onPubkeyChanged = onDnsttPubkeyChanged,
                        onE2eTimeoutChanged = onDnsttE2eTimeoutChanged,
                        onE2eUrlChanged = onDnsttE2eUrlChanged,
                        onSocksUsernameChanged = onDnsttSocksUsernameChanged,
                        onSocksPasswordChanged = onDnsttSocksPasswordChanged,
                        onToggleNearbyIps = onToggleDnsttNearbyIps,
                        dnsttSort = state.dnsttSort,
                        onDnsttSortChange = onDnsttSortChanged,
                        onCopyResults = {
                            val e2eRequested = state.dnsttConfigDraft.pubkey.isNotBlank()
                            copyToClipboard(
                                label = "DNSTT IP addresses",
                                content = buildDnsttCopyText(
                                    resolvers = loadAllDnsttResolvers(),
                                    e2eRequested = e2eRequested,
                                ),
                                emptyMessage = if (e2eRequested) {
                                    "No successful DNSTT E2E results to copy."
                                } else {
                                    "No successful DNSTT tunnel results to copy."
                                },
                            )
                        },
                        onExportResults = {
                            val e2eRequested = state.dnsttConfigDraft.pubkey.isNotBlank()
                            exportDocument(
                                prefix = "dnstt-results",
                                content = buildDnsttExportText(
                                    resolvers = loadAllDnsttResolvers(),
                                    e2eRequested = e2eRequested,
                                ),
                                emptyMessage = if (e2eRequested) {
                                    "No successful DNSTT E2E results to export."
                                } else {
                                    "No successful DNSTT tunnel results to export."
                                },
                            )
                        },
                        onCopyFailures = {
                            val e2eRequested = state.dnsttConfigDraft.pubkey.isNotBlank()
                            copyToClipboard(
                                label = "DNSTT failed IP addresses",
                                content = buildDnsttFailureCopyText(
                                    resolvers = loadAllDnsttResolvers(),
                                    e2eRequested = e2eRequested,
                                ),
                                emptyMessage = if (e2eRequested) {
                                    "No failed DNSTT E2E results to copy."
                                } else {
                                    "No failed DNSTT tunnel results to copy."
                                },
                            )
                        },
                        onExportFailures = {
                            val e2eRequested = state.dnsttConfigDraft.pubkey.isNotBlank()
                            exportDocument(
                                prefix = "dnstt-failures",
                                content = buildDnsttFailureExportText(
                                    resolvers = loadAllDnsttResolvers(),
                                    e2eRequested = e2eRequested,
                                ),
                                emptyMessage = if (e2eRequested) {
                                    "No failed DNSTT E2E results to export."
                                } else {
                                    "No failed DNSTT tunnel results to export."
                                },
                            )
                        },
                        onCopyResultIp = { ip -> copySingleIp(ip, "DNSTT IP") },
                        onLoadMoreDnstt = onLoadMoreDnstt,
                        onLoadMoreDnsttFailures = onLoadMoreDnsttFailures,
                        onStartDnstt = onStartDnstt,
                        onCancelDnstt = onCancelDnstt,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ModernStatusBanner(
    state: ScannerUiState,
    progressFraction: Float,
    onCancel: () -> Unit,
) {
    val successCount = if (state.sessionStatus == SessionStatus.RUNNING) {
        state.progress.qualified
    } else {
        state.resolverCount
    }
    val failedCount = if (state.sessionStatus == SessionStatus.RUNNING) {
        (state.progress.scanned - state.progress.qualified).coerceAtLeast(0L)
    } else {
        state.failureCount
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = CardSurface,
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .background(
                                color = when (state.sessionStatus) {
                                    SessionStatus.RUNNING -> NeonBlue
                                    SessionStatus.COMPLETED -> SuccessGreen
                                    SessionStatus.FAILED -> ErrorPink
                                    SessionStatus.CANCELLED -> WarningAmber
                                    else -> TextSecondary
                                },
                                shape = CircleShape
                            )
                    )
                    Text(
                        text = when (state.sessionStatus) {
                            SessionStatus.RUNNING -> "Scanning"
                            SessionStatus.COMPLETED -> "Completed"
                            SessionStatus.FAILED -> "Failed"
                            SessionStatus.CANCELLED -> "Cancelled"
                            else -> "Ready"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                }
                if (state.sessionStatus == SessionStatus.RUNNING) {
                    IconButton(
                        onClick = onCancel,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = "Cancel",
                            tint = TextSecondary
                        )
                    }
                }
            }

            if (state.progress.total > 0) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(BorderGlow)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(progressFraction)
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp))
                            .background(NeonBlue)
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "${state.progress.scanned} / ${state.progress.total}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                    Text(
                        text = "${(progressFraction * 100).toInt()}%",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = NeonBlue
                    )
                }
            }

            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ModernStatChip("Success", successCount.toString(), SuccessGreen)
                ModernStatChip("Failed", failedCount.toString(), ErrorPink)
            }

            if (state.transparentProxyDetected) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(WarningAmber.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                        .border(1.dp, WarningAmber.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                        .padding(10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.Warning,
                        contentDescription = null,
                        tint = WarningAmber,
                        modifier = Modifier.size(18.dp)
                    )
                    Text(
                        text = "Transparent DNS proxy detected",
                        style = MaterialTheme.typography.bodySmall,
                        color = WarningAmber,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ModernDnsttStatusBanner(
    state: ScannerUiState,
    onCancel: () -> Unit,
) {
    val progress = state.dnsttProgress
    val progressFraction = if (progress.total > 0) {
        (progress.checked.toFloat() / progress.total.toFloat()).coerceIn(0f, 1f)
    } else {
        0f
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CardSurface),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .background(
                                when (state.dnsttSessionStatus) {
                                    SessionStatus.RUNNING -> NeonBlue
                                    SessionStatus.COMPLETED -> SuccessGreen
                                    SessionStatus.FAILED -> ErrorPink
                                    SessionStatus.CANCELLED -> WarningAmber
                                    else -> TextSecondary
                                },
                                CircleShape,
                            ),
                    )
                    Text(
                        text = when (state.dnsttSessionStatus) {
                            SessionStatus.RUNNING -> "DNSTT Running"
                            SessionStatus.COMPLETED -> "DNSTT Completed"
                            SessionStatus.FAILED -> "DNSTT Failed"
                            SessionStatus.CANCELLED -> "DNSTT Cancelled"
                            else -> "DNSTT Ready"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary,
                    )
                }
                if (state.dnsttSessionStatus == SessionStatus.RUNNING) {
                    IconButton(
                        onClick = onCancel,
                        modifier = Modifier.size(32.dp),
                    ) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = "Cancel DNSTT",
                            tint = TextSecondary,
                        )
                    }
                }
            }

            if (progress.total > 0) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(BorderGlow),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(progressFraction)
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp))
                            .background(NeonBlue),
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "${progress.checked} / ${progress.total}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary,
                    )
                    Text(
                        text = "${(progressFraction * 100).toInt()}%",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = NeonBlue,
                    )
                }
            }

            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ModernStatChip("Checked", progress.checked.toString(), NeonBlue)
                ModernStatChip("Tunnel OK", progress.tunnelOk.toString(), SuccessGreen)
                ModernStatChip("E2E OK", progress.e2eOk.toString(), InfoCyan)
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ModernScanTab(
    state: ScannerUiState,
    progressFraction: Float,
    importInProgress: Boolean,
    onTargetInputChanged: (String) -> Unit,
    onImportWhiteDnsList: (WhiteDnsListOption) -> Unit,
    onImportTargetsFile: () -> Unit,
    onLoadTargets: () -> Unit,
    onWorkersChanged: (String) -> Unit,
    onTimeoutChanged: (String) -> Unit,
    onPortChanged: (String) -> Unit,
    onProbeDomainChanged: (String) -> Unit,
    onScoreThresholdChanged: (String) -> Unit,
    onProtocolSelected: (ScanTransport) -> Unit,
    successSort: SuccessSortOption,
    onSuccessSortChange: (SuccessSortOption) -> Unit,
    filter: String,
    onFilterChange: (String) -> Unit,
    onCopySuccess: () -> Unit,
    onExportSuccess: () -> Unit,
    onCopyFailures: () -> Unit,
    onExportFailures: () -> Unit,
    onCopyFailureIp: (String) -> Unit,
    onLoadMoreSuccess: () -> Unit,
    onLoadMoreFailures: () -> Unit,
    onStartScan: () -> Unit,
    onCancelScan: () -> Unit,
) {
    val scanRunning = state.sessionStatus == SessionStatus.RUNNING
    var scanConfigExpanded by remember { mutableStateOf(false) }
    var importMenuExpanded by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.sessionStatus == SessionStatus.RUNNING || state.progress.total > 0) {
            item {
                ModernStatusBanner(
                    state = state,
                    progressFraction = progressFraction,
                    onCancel = onCancelScan,
                )
            }
        }

        item {
            ModernCard(title = "Scan Targets") {
                Text(
                    text = "Enter IPv4 addresses (CIDR or single IPs)",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Box {
                    OutlinedButton(
                        onClick = { importMenuExpanded = true },
                        enabled = !importInProgress,
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = NeonBlue,
                        ),
                        border = BorderStroke(1.dp, NeonBlue.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(10.dp),
                    ) {
                        Text(
                            text = if (importInProgress) "Importing..." else "Import",
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    DropdownMenu(
                        expanded = importMenuExpanded,
                        onDismissRequest = { importMenuExpanded = false },
                    ) {
                        WhiteDnsListOption.entries.forEach { option ->
                            DropdownMenuItem(
                                text = { Text("Import ${option.label}") },
                                onClick = {
                                    importMenuExpanded = false
                                    onImportWhiteDnsList(option)
                                },
                            )
                        }
                        DropdownMenuItem(
                            text = { Text("Import File (txt)") },
                            onClick = {
                                importMenuExpanded = false
                                onImportTargetsFile()
                            },
                        )
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedTextField(
                    value = state.targetInput,
                    onValueChange = onTargetInputChanged,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(160.dp),
                    placeholder = {
                        Text(
                            "192.168.1.0/24\n10.0.0.1\n# Comments supported",
                            color = TextTertiary
                        )
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NeonBlue,
                        unfocusedBorderColor = BorderGlow,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedContainerColor = MutedSurface,
                        unfocusedContainerColor = MutedSurface,
                        disabledContainerColor = MutedSurface,
                        cursorColor = NeonBlue,
                    ),
                    shape = RoundedCornerShape(12.dp),
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = onLoadTargets,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MutedSurface,
                        contentColor = NeonBlue,
                    ),
                    border = BorderStroke(1.dp, NeonBlue),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("Load Targets", fontWeight = FontWeight.SemiBold)
                }

                if (state.parsedTargets.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        ModernStatChip("Ranges", state.parsedTargets.size.toString(), AccentCyan)
                        ModernStatChip("Addresses", state.totalAddresses.toString(), InfoCyan)
                        ModernStatChip("Hosts", state.totalScanHosts.toString(), NeonBlue)
                    }
                }
            }
        }

        // Warnings
        if (state.parseWarnings.isNotEmpty()) {
            item {
                AlertCard(
                    icon = Icons.Filled.Warning,
                    title = "Warnings",
                    messages = state.parseWarnings,
                    color = WarningAmber,
                )
            }
        }

        // Errors
        if (state.lastError != null && state.sessionStatus != SessionStatus.RUNNING) {
            item {
                AlertCard(
                    icon = Icons.Filled.Warning,
                    title = "Error",
                    messages = listOf(state.lastError),
                    color = ErrorPink,
                )
            }
        }

        item {
            ModernCollapsibleCard(
                title = "Scan Configuration",
                accentColor = NeonBlue,
                expanded = scanConfigExpanded,
                onToggle = { scanConfigExpanded = !scanConfigExpanded },
            ) {
                ConfigFieldSection(
                    title = "Protocol",
                    description = "DNS query transport method"
                )
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    ScanTransport.entries.forEach { protocol ->
                        FilterChip(
                            selected = state.configDraft.protocol == protocol,
                            onClick = { onProtocolSelected(protocol) },
                            label = { Text(protocol.name) },
                            colors = FilterChipDefaults.filterChipColors(
                                containerColor = MutedSurface,
                                selectedContainerColor = NeonBlue.copy(alpha = 0.15f),
                                labelColor = TextSecondary,
                                selectedLabelColor = NeonBlue,
                            ),
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (state.configDraft.protocol == protocol) NeonBlue else BorderGlow
                            ),
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(InfoCyan.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
                        .border(1.dp, InfoCyan.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = when (state.configDraft.protocol) {
                            ScanTransport.UDP -> "UDP: Fast, connectionless queries (most common)"
                            ScanTransport.TCP -> "TCP: Reliable, connection-based queries"
                            ScanTransport.BOTH -> "BOTH: Test using UDP and TCP protocols"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = InfoCyan,
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))
                ConfigFieldSection(
                    title = "Performance",
                    description = "Scan speed and resource usage"
                )
                Spacer(modifier = Modifier.height(6.dp))
                ModernFieldRow(
                    leftLabel = "Workers",
                    leftValue = state.configDraft.workers,
                    onLeftChange = onWorkersChanged,
                    leftDescription = "Concurrent DNS workers (1-8, default: 8)",
                    rightLabel = "Timeout (ms)",
                    rightValue = state.configDraft.timeoutMillis,
                    onRightChange = onTimeoutChanged,
                    rightDescription = "DNS query timeout (500-60000 ms, default: 15000)",
                )

                Spacer(modifier = Modifier.height(12.dp))
                ConfigFieldSection(
                    title = "DNS Settings",
                    description = "DNS query parameters"
                )
                Spacer(modifier = Modifier.height(6.dp))
                ModernFieldRow(
                    leftLabel = "Port",
                    leftValue = state.configDraft.port,
                    onLeftChange = onPortChanged,
                    leftDescription = "DNS port (default: 53)",
                    rightLabel = "DNSTT Min Score",
                    rightValue = state.configDraft.scoreThreshold,
                    onRightChange = onScoreThresholdChanged,
                    rightDescription = "Resolver score needed for DNSTT (1-6, default: 2)",
                )

                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ModernTextField(
                        value = state.configDraft.probeDomain,
                        onValueChange = onProbeDomainChanged,
                        label = "Probe Domain",
                    )
                    Text(
                        text = "Hostname used for DNS test queries (e.g., example.com)",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextTertiary,
                    )
                }

            }
        }

        item {
            Button(
                onClick = if (scanRunning) onCancelScan else onStartScan,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (scanRunning) ErrorPink else NeonBlue,
                    contentColor = PrimaryForeground,
                ),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = if (scanRunning) "Stop Scan DNS" else "Start Scan DNS",
                    fontWeight = FontWeight.Bold,
                )
            }
        }

        item {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = filter == "all",
                    onClick = { onFilterChange("all") },
                    label = { Text("All (${state.resolverCount + state.failureCount})") },
                    colors = FilterChipDefaults.filterChipColors(
                        containerColor = MutedSurface,
                        selectedContainerColor = NeonBlue.copy(alpha = 0.15f),
                        labelColor = TextSecondary,
                        selectedLabelColor = NeonBlue,
                    ),
                    border = BorderStroke(
                        width = 1.dp,
                        color = if (filter == "all") NeonBlue else BorderGlow,
                    ),
                )
                FilterChip(
                    selected = filter == "success",
                    onClick = { onFilterChange("success") },
                    label = { Text("Success (${state.resolverCount})") },
                    colors = FilterChipDefaults.filterChipColors(
                        containerColor = MutedSurface,
                        selectedContainerColor = SuccessGreen.copy(alpha = 0.15f),
                        labelColor = TextSecondary,
                        selectedLabelColor = SuccessGreen,
                    ),
                    border = BorderStroke(
                        width = 1.dp,
                        color = if (filter == "success") SuccessGreen else BorderGlow,
                    ),
                )
                FilterChip(
                    selected = filter == "failures",
                    onClick = { onFilterChange("failures") },
                    label = { Text("Failures (${state.failureCount})") },
                    colors = FilterChipDefaults.filterChipColors(
                        containerColor = MutedSurface,
                        selectedContainerColor = ErrorPink.copy(alpha = 0.15f),
                        labelColor = TextSecondary,
                        selectedLabelColor = ErrorPink,
                    ),
                    border = BorderStroke(
                        width = 1.dp,
                        color = if (filter == "failures") ErrorPink else BorderGlow,
                    ),
                )
            }
        }

        if (filter == "all" || filter == "success") {
            item {
                ModernSectionHeader(
                    title = "Successful Resolvers",
                    count = state.resolverCount,
                    color = SuccessGreen,
                    onCopy = onCopySuccess,
                    onExport = onExportSuccess,
                )
            }

            item {
                SuccessSortChips(
                    selectedSort = successSort,
                    onSortChange = onSuccessSortChange,
                )
            }

            if (state.resolverCount == 0L) {
                item {
                    EmptyStateCard(
                        icon = Icons.Filled.CheckCircle,
                        message = if (state.sessionStatus == SessionStatus.RUNNING) {
                            "Scanning for resolvers..."
                        } else {
                            "No successful resolvers found"
                        },
                        color = SuccessGreen,
                    )
                }
            } else {
                itemsIndexed(
                    items = state.resolvers,
                    key = { index, resolver -> "${resolver.ip}-${resolver.prefix}-${resolver.transport.name}-$index" },
                ) { index, resolver ->
                    AutoLoadMoreItemTrigger(
                        index = index,
                        loadedCount = state.resolvers.size,
                        totalCount = state.resolverCount,
                        onLoadMore = onLoadMoreSuccess,
                    )
                    CompactResolverCard(resolver = resolver)
                }
            }
        }

        if (filter == "all" || filter == "failures") {
            if (filter == "all") {
                item { Spacer(modifier = Modifier.height(8.dp)) }
            }

            item {
                ModernSectionHeader(
                    title = "Failures",
                    count = state.failureCount,
                    color = ErrorPink,
                    onCopy = onCopyFailures,
                    onExport = onExportFailures,
                )
            }

            if (state.failureCount == 0L) {
                item {
                    EmptyStateCard(
                        icon = Icons.Filled.Warning,
                        message = if (state.sessionStatus == SessionStatus.RUNNING) {
                            "No failures yet..."
                        } else {
                            "No failures recorded"
                        },
                        color = ErrorPink,
                    )
                }
            } else {
                itemsIndexed(
                    items = state.failures,
                    key = { index, failure -> "${failure.ip}-${failure.prefix}-$index" },
                ) { index, failure ->
                    AutoLoadMoreItemTrigger(
                        index = index,
                        loadedCount = state.failures.size,
                        totalCount = state.failureCount,
                        onLoadMore = onLoadMoreFailures,
                    )
                    CompactFailureCard(
                        failure = failure,
                        onCopyIp = onCopyFailureIp,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ModernDnsttTab(
    state: ScannerUiState,
    onWorkersChanged: (String) -> Unit,
    onTimeoutChanged: (String) -> Unit,
    onTransportSelected: (DnsttTransport) -> Unit,
    onDomainChanged: (String) -> Unit,
    onPubkeyChanged: (String) -> Unit,
    onE2eTimeoutChanged: (String) -> Unit,
    onE2eUrlChanged: (String) -> Unit,
    onSocksUsernameChanged: (String) -> Unit,
    onSocksPasswordChanged: (String) -> Unit,
    onToggleNearbyIps: () -> Unit,
    dnsttSort: DnsttSortOption,
    onDnsttSortChange: (DnsttSortOption) -> Unit,
    onCopyResults: () -> Unit,
    onExportResults: () -> Unit,
    onCopyFailures: () -> Unit,
    onExportFailures: () -> Unit,
    onCopyResultIp: (String) -> Unit,
    onLoadMoreDnstt: () -> Unit,
    onLoadMoreDnsttFailures: () -> Unit,
    onStartDnstt: () -> Unit,
    onCancelDnstt: () -> Unit,
) {
    val showE2eFields = state.dnsttConfigDraft.pubkey.isNotBlank()
    val dnsttRunning = state.dnsttSessionStatus == SessionStatus.RUNNING
    val visibleSuccessResolvers = state.dnsttResolvers
    val visibleFailureResolvers = state.dnsttFailures
    val progressSuccessCount = if (showE2eFields) {
        state.dnsttProgress.e2eOk
    } else {
        state.dnsttProgress.tunnelOk
    }
    val successCount = maxOf(progressSuccessCount, state.dnsttResolverCount)
    val failureCount = maxOf(
        (state.dnsttProgress.checked - progressSuccessCount).coerceAtLeast(0L),
        state.dnsttFailureCount,
    )
    var dnsttConfigExpanded by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.dnsttSessionStatus == SessionStatus.RUNNING || state.dnsttProgress.total > 0) {
            item {
                ModernDnsttStatusBanner(
                    state = state,
                    onCancel = onCancelDnstt,
                )
            }
        }

        item {
            ModernCollapsibleCard(
                title = "DNSTT Configuration",
                accentColor = NeonBlue,
                expanded = dnsttConfigExpanded,
                onToggle = { dnsttConfigExpanded = !dnsttConfigExpanded },
            ) {
                Text(
                    text = "Uses qualified DNS results with separate runtime controls and results",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Spacer(modifier = Modifier.height(12.dp))
                ConfigFieldSection(
                    title = "Runtime",
                    description = "Tunnel-only mode without pubkey, full E2E with pubkey",
                )
                Spacer(modifier = Modifier.height(6.dp))
                ModernFieldRow(
                    leftLabel = "Workers",
                    leftValue = state.dnsttConfigDraft.workers,
                    onLeftChange = onWorkersChanged,
                    leftDescription = "Concurrent DNSTT workers",
                    rightLabel = "Timeout (ms)",
                    rightValue = state.dnsttConfigDraft.timeoutMillis,
                    onRightChange = onTimeoutChanged,
                    rightDescription = "Tunnel precheck timeout",
                )

                Spacer(modifier = Modifier.height(12.dp))
                ConfigFieldSection(
                    title = "Transport",
                    description = "DNS transport for embedded DNSTT client",
                )
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    DnsttTransport.entries.forEach { transport ->
                        FilterChip(
                            selected = state.dnsttConfigDraft.transport == transport,
                            onClick = { onTransportSelected(transport) },
                            label = { Text(transport.name) },
                            colors = FilterChipDefaults.filterChipColors(
                                containerColor = MutedSurface,
                                selectedContainerColor = NeonBlue.copy(alpha = 0.15f),
                                labelColor = TextSecondary,
                                selectedLabelColor = NeonBlue,
                            ),
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (state.dnsttConfigDraft.transport == transport) NeonBlue else BorderGlow,
                            ),
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ModernTextField(
                        value = state.dnsttConfigDraft.domain,
                        onValueChange = onDomainChanged,
                        label = "DNSTT Domain",
                    )
                    Text(
                        text = "Tunnel domain for precheck and E2E runs",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextTertiary,
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ModernTextField(
                        value = state.dnsttConfigDraft.pubkey,
                        onValueChange = onPubkeyChanged,
                        label = "DNSTT Pubkey",
                    )
                    Text(
                        text = "Empty for tunnel-only, set for full E2E over SOCKS",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextTertiary,
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        ModernTextField(
                            value = state.dnsttConfigDraft.e2eTimeoutSeconds,
                            onValueChange = onE2eTimeoutChanged,
                            label = "E2E Timeout (s)",
                            modifier = Modifier.fillMaxWidth(),
                            keyboardType = KeyboardType.Number,
                        )
                        Text(
                            text = "Required only with pubkey",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextTertiary,
                        )
                    }
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        ModernTextField(
                            value = state.dnsttConfigDraft.socksUsername,
                            onValueChange = onSocksUsernameChanged,
                            label = "SOCKS Username",
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            text = "Optional SOCKS auth",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextTertiary,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ModernTextField(
                        value = state.dnsttConfigDraft.socksPassword,
                        onValueChange = onSocksPasswordChanged,
                        label = "SOCKS Password",
                    )
                    Text(
                        text = "Required only if SOCKS auth is enabled",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextTertiary,
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ModernTextField(
                        value = state.dnsttConfigDraft.e2eUrl,
                        onValueChange = onE2eUrlChanged,
                        label = "E2E URL",
                    )
                    Text(
                        text = if (showE2eFields) {
                            "URL fetched through local DNSTT SOCKS"
                        } else {
                            "Inactive until pubkey is set"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextTertiary,
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MutedSurface, RoundedCornerShape(12.dp))
                        .border(1.dp, BorderGlow, RoundedCornerShape(12.dp))
                        .clickable(onClick = onToggleNearbyIps)
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = "Test Nearby IPs",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary,
                        )
                        Text(
                            text = "After success, sweep the rest of /24 subnet",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Switch(
                        checked = state.dnsttConfigDraft.testNearbyIps,
                        onCheckedChange = { onToggleNearbyIps() },
                    )
                }
            }
        }

        item {
            Button(
                onClick = if (dnsttRunning) onCancelDnstt else onStartDnstt,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (dnsttRunning) ErrorPink else NeonBlue,
                    contentColor = PrimaryForeground,
                ),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = if (dnsttRunning) "Stop DNSTT E2E" else "Start DNSTT E2E",
                    fontWeight = FontWeight.Bold,
                )
            }
        }

        if (state.dnsttLastError != null && state.dnsttSessionStatus != SessionStatus.RUNNING) {
            item {
                AlertCard(
                    icon = Icons.Filled.Warning,
                    title = "DNSTT Error",
                    messages = listOfNotNull(state.dnsttLastError),
                    color = ErrorPink,
                )
            }
        }

        item {
            DnsttSortChips(
                selectedSort = dnsttSort,
                onSortChange = onDnsttSortChange,
            )
        }

        item {
            ModernSectionHeader(
                title = if (showE2eFields) "DNSTT E2E Success" else "DNSTT Tunnel Success",
                count = successCount,
                color = SuccessGreen,
                onCopy = onCopyResults,
                onExport = onExportResults,
            )
        }

        if (successCount == 0L) {
            item {
                EmptyStateCard(
                    icon = Icons.Filled.CheckCircle,
                    message = if (state.dnsttSessionStatus == SessionStatus.RUNNING) {
                        "Checking qualified resolvers with DNSTT..."
                    } else {
                        if (showE2eFields) {
                            "No successful DNSTT E2E results yet"
                        } else {
                            "No successful DNSTT tunnel results yet"
                        }
                    },
                    color = SuccessGreen,
                )
            }
        } else {
            itemsIndexed(
                items = visibleSuccessResolvers,
                key = { index, resolver -> "${resolver.ip}-${resolver.prefix}-${resolver.dnsttNearby}-$index" },
            ) { index, resolver ->
                AutoLoadMoreItemTrigger(
                    index = index,
                    loadedCount = visibleSuccessResolvers.size,
                    totalCount = successCount,
                    onLoadMore = onLoadMoreDnstt,
                )
                CompactDnsttResolverCard(
                    resolver = resolver,
                    e2eRequested = showE2eFields,
                    onCopyIp = onCopyResultIp,
                )
            }
        }

        item { Spacer(modifier = Modifier.height(8.dp)) }

        item {
            ModernSectionHeader(
                title = if (showE2eFields) "DNSTT E2E Failures" else "DNSTT Tunnel Failures",
                count = failureCount,
                color = ErrorPink,
                onCopy = onCopyFailures,
                onExport = onExportFailures,
            )
        }

        if (failureCount == 0L) {
            item {
                EmptyStateCard(
                    icon = Icons.Filled.Warning,
                    message = if (state.dnsttSessionStatus == SessionStatus.RUNNING) {
                        "No DNSTT failures yet..."
                    } else {
                        "No DNSTT failures recorded"
                    },
                    color = ErrorPink,
                )
            }
        } else {
            itemsIndexed(
                items = visibleFailureResolvers,
                key = { index, resolver -> "${resolver.ip}-${resolver.prefix}-${resolver.dnsttNearby}-failure-$index" },
            ) { index, resolver ->
                AutoLoadMoreItemTrigger(
                    index = index,
                    loadedCount = visibleFailureResolvers.size,
                    totalCount = failureCount,
                    onLoadMore = onLoadMoreDnsttFailures,
                )
                CompactDnsttResolverCard(
                    resolver = resolver,
                    e2eRequested = showE2eFields,
                    onCopyIp = onCopyResultIp,
                )
            }
        }
    }
}

@Composable
private fun ModernCard(
    title: String,
    content: @Composable () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = CardSurface,
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = TextPrimary,
            )
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
private fun ModernCollapsibleCard(
    title: String,
    accentColor: Color,
    expanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = CardSurface,
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary,
                )
                OutlinedButton(
                    onClick = onToggle,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = accentColor),
                    border = BorderStroke(1.dp, accentColor.copy(alpha = 0.45f)),
                    shape = RoundedCornerShape(10.dp),
                ) {
                    Text(
                        text = if (expanded) "Hide" else "Show",
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }

            if (expanded) {
                Spacer(modifier = Modifier.height(16.dp))
                content()
            }
        }
    }
}

@Composable
private fun AlertCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    messages: List<String>,
    color: Color,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.12f),
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, color.copy(alpha = 0.4f)),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(18.dp)
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = color,
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            messages.forEach { message ->
                Text(
                    text = "• $message",
                    style = MaterialTheme.typography.bodySmall,
                    color = color,
                )
            }
        }
    }
}

@Composable
private fun ModernStatChip(
    label: String,
    value: String,
    color: Color,
) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    ) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .background(color, CircleShape)
            )
            Text(
                text = "$label: ",
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Bold,
                color = color,
            )
        }
    }
}

@Composable
private fun ConfigFieldSection(
    title: String,
    description: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = TextPrimary,
        )
        Text(
            text = description,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
    }
}

@Composable
private fun ModernTargetRow(entry: PrefixEntry) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MutedSurface, RoundedCornerShape(8.dp))
            .border(1.dp, BorderGlow, RoundedCornerShape(8.dp))
            .padding(10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = entry.prefix,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
                color = NeonBlue,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "${entry.totalAddresses} addresses • ${entry.scanHosts} hosts",
                style = MaterialTheme.typography.bodySmall,
                color = TextTertiary,
            )
        }
    }
}

@Composable
private fun ModernFieldRow(
    leftLabel: String,
    leftValue: String,
    onLeftChange: (String) -> Unit,
    leftDescription: String = "",
    rightLabel: String,
    rightValue: String,
    onRightChange: (String) -> Unit,
    rightDescription: String = "",
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            ModernTextField(
                value = leftValue,
                onValueChange = onLeftChange,
                label = leftLabel,
                modifier = Modifier.fillMaxWidth(),
                keyboardType = KeyboardType.Number,
            )
            if (leftDescription.isNotEmpty()) {
                Text(
                    text = leftDescription,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextTertiary,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            ModernTextField(
                value = rightValue,
                onValueChange = onRightChange,
                label = rightLabel,
                modifier = Modifier.fillMaxWidth(),
                keyboardType = KeyboardType.Number,
            )
            if (rightDescription.isNotEmpty()) {
                Text(
                    text = rightDescription,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextTertiary,
                )
            }
        }
    }
}

@Composable
private fun ModernTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, color = TextSecondary) },
        modifier = modifier,
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = NeonBlue,
            unfocusedBorderColor = BorderGlow,
            focusedTextColor = TextPrimary,
            unfocusedTextColor = TextPrimary,
            focusedContainerColor = MutedSurface,
            unfocusedContainerColor = MutedSurface,
            disabledContainerColor = MutedSurface,
            cursorColor = NeonBlue,
        ),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        singleLine = true,
        shape = RoundedCornerShape(12.dp),
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SuccessSortChips(
    selectedSort: SuccessSortOption,
    onSortChange: (SuccessSortOption) -> Unit,
) {
    ResultSortChips(
        options = listOf(
            SortChipOption(SuccessSortOption.DNS_SCORE, "DNS Score", SuccessGreen),
            SortChipOption(SuccessSortOption.TUNNEL_SPEED, "Tunnel Speed", InfoCyan),
            SortChipOption(SuccessSortOption.E2E_SPEED, "E2E Speed", NeonBlue),
        ),
        selectedSort = selectedSort,
        onSortChange = onSortChange,
    )
}

@Composable
private fun DnsttSortChips(
    selectedSort: DnsttSortOption,
    onSortChange: (DnsttSortOption) -> Unit,
) {
    ResultSortChips(
        options = listOf(
            SortChipOption(DnsttSortOption.TUNNEL_SPEED, "Tunnel Speed", InfoCyan),
            SortChipOption(DnsttSortOption.E2E_SPEED, "E2E Speed", NeonBlue),
        ),
        selectedSort = selectedSort,
        onSortChange = onSortChange,
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun <T> ResultSortChips(
    options: List<SortChipOption<T>>,
    selectedSort: T,
    onSortChange: (T) -> Unit,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        options.forEach { option ->
            FilterChip(
                selected = selectedSort == option.value,
                onClick = { onSortChange(option.value) },
                label = { Text(option.label) },
                colors = FilterChipDefaults.filterChipColors(
                    containerColor = MutedSurface,
                    selectedContainerColor = option.color.copy(alpha = 0.15f),
                    labelColor = TextSecondary,
                    selectedLabelColor = option.color,
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = if (selectedSort == option.value) option.color else BorderGlow,
                ),
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ModernSectionHeader(
    title: String,
    count: Long,
    color: Color,
    onCopy: () -> Unit,
    onExport: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = CardSurface,
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(color, CircleShape),
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Box(
                    modifier = Modifier
                        .background(color.copy(alpha = 0.2f), CircleShape)
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                ) {
                    Text(
                        count.toString(),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (color == NeonBlue) PrimaryForeground else color,
                    )
                }
            }

            if (count > 0) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(
                        onClick = onCopy,
                        modifier = Modifier
                            .height(32.dp)
                            .defaultMinSize(minWidth = 0.dp, minHeight = 0.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = color,
                        ),
                        border = BorderStroke(1.dp, color.copy(alpha = 0.5f)),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                    ) {
                        Text("Copy", fontSize = 12.sp)
                    }
                    OutlinedButton(
                        onClick = onExport,
                        modifier = Modifier
                            .height(32.dp)
                            .defaultMinSize(minWidth = 0.dp, minHeight = 0.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = color,
                        ),
                        border = BorderStroke(1.dp, color.copy(alpha = 0.5f)),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                    ) {
                        Text("Export", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CompactResolverCard(
    resolver: ResolverRecord,
) {
    ResolverResultCard(
        resolver = resolver,
        accentColor = SuccessGreen,
        ipColor = SuccessGreen,
        statusText = "Success",
        statusColor = SuccessGreen,
        metrics = resolverResultMetrics(resolver),
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CompactDnsttResolverCard(
    resolver: ResolverRecord,
    e2eRequested: Boolean,
    onCopyIp: (String) -> Unit,
) {
    val passed = if (e2eRequested) resolver.dnsttE2eOk else resolver.dnsttTunnelOk
    val accentColor = when {
        passed -> SuccessGreen
        resolver.dnsttChecked -> ErrorPink
        else -> TextSecondary
    }

    ResolverResultCard(
        resolver = resolver,
        accentColor = accentColor,
        ipColor = accentColor,
        statusText = when {
            resolver.dnsttE2eOk -> "E2E OK"
            resolver.dnsttTunnelOk -> "Tunnel OK"
            resolver.dnsttChecked -> "Failed"
            else -> "Pending"
        },
        statusColor = accentColor,
        badges = if (resolver.dnsttNearby) {
            listOf(ResultBadge("Nearby", WarningAmber))
        } else {
            emptyList()
        },
        metrics = resolverResultMetrics(resolver),
        errorText = resolver.dnsttError.ifBlank { null },
        onClick = { onCopyIp(resolver.ip) },
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ResolverResultCard(
    resolver: ResolverRecord,
    accentColor: Color,
    ipColor: Color,
    statusText: String,
    statusColor: Color,
    metrics: List<ResultMetric>,
    badges: List<ResultBadge> = emptyList(),
    errorText: String? = null,
    onClick: (() -> Unit)? = null,
) {
    val clickModifier = if (onClick == null) {
        Modifier
    } else {
        Modifier.clickable { onClick() }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(accentColor.copy(alpha = 0.1f), RoundedCornerShape(8.dp))
            .border(1.dp, accentColor.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
            .then(clickModifier)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .background(accentColor, CircleShape),
                    )
                    Text(
                        text = resolver.ip,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = ipColor,
                    )
                    badges.forEach { badge ->
                        Text(
                            text = badge.label,
                            style = MaterialTheme.typography.labelSmall,
                            color = badge.color,
                        )
                    }
                }
                Text(
                    text = resolver.prefix,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextTertiary,
                )
                if (!errorText.isNullOrBlank()) {
                    Text(
                        text = errorText,
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                        maxLines = 2,
                    )
                }
            }

            Text(
                text = statusText,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Bold,
                color = statusColor,
            )
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            metrics.forEach { metric ->
                ResultMetricChip(metric)
            }
        }
    }
}

@Composable
private fun ResultMetricChip(metric: ResultMetric) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = metric.label,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
        Text(
            text = metric.value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = metric.color,
        )
    }
}

private fun resolverResultMetrics(
    resolver: ResolverRecord,
): List<ResultMetric> {
    val metrics = mutableListOf(
        ResultMetric(
            label = resolver.transport.name,
            value = "${resolver.tunnelScore}/6",
            color = if (resolver.tunnelScore >= 4) SuccessGreen else WarningAmber,
        ),
        ResultMetric(
            label = "DNS",
            value = "${resolver.latencyMillis}ms",
            color = InfoCyan,
        ),
    )
    if (resolver.dnsttTunnelMillis > 0) {
        metrics += ResultMetric(
            label = "Tunnel",
            value = "${resolver.dnsttTunnelMillis}ms",
            color = InfoCyan,
        )
    }
    if (resolver.dnsttE2eMillis > 0) {
        metrics += ResultMetric(
            label = "E2E",
            value = "${resolver.dnsttE2eMillis}ms",
            color = NeonBlue,
        )
    }
    return metrics
}

@Composable
private fun CompactFailureCard(
    failure: FailureRecord,
    onCopyIp: (String) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(ErrorPink.copy(alpha = 0.08f), RoundedCornerShape(8.dp))
            .border(1.dp, ErrorPink.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
            .clickable { onCopyIp(failure.ip) }
            .padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .background(ErrorPink, CircleShape),
        )
        Text(
            text = failure.ip,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = ErrorPink,
            maxLines = 1,
        )
        Text(
            text = compactFailureReason(failure.reason),
            modifier = Modifier.weight(1f),
            fontSize = 11.sp,
            color = TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun AutoLoadMoreItemTrigger(
    index: Int,
    loadedCount: Int,
    totalCount: Long,
    onLoadMore: () -> Unit,
    preloadOffset: Int = 4,
) {
    val latestOnLoadMore by rememberUpdatedState(onLoadMore)
    val triggerIndex = (loadedCount - 1 - preloadOffset).coerceAtLeast(0)
    if (totalCount > loadedCount.toLong() && index == triggerIndex) {
        LaunchedEffect(loadedCount, totalCount) {
            latestOnLoadMore()
        }
    }
}

@Composable
private fun EmptyStateCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    message: String,
    color: Color,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = CardSurface,
        ),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderGlow),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = color.copy(alpha = 0.5f),
                modifier = Modifier.size(32.dp)
            )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
            )
        }
    }
}

// Helper functions
private fun buildSuccessCopyText(resolvers: List<ResolverRecord>): String {
    val successfulResolvers = resolvers.onlySuccessfulDnsResolvers()
    if (successfulResolvers.isEmpty()) {
        return ""
    }
    return successfulResolvers.joinToString("\n") { it.ip }
}

private fun buildFailureCopyText(failures: List<FailureRecord>): String {
    if (failures.isEmpty()) {
        return ""
    }
    return failures.joinToString("\n") { it.ip }
}

private fun buildSuccessExportText(resolvers: List<ResolverRecord>): String {
    return buildSuccessCopyText(resolvers)
}

private fun buildFailureExportText(failures: List<FailureRecord>): String {
    return buildFailureCopyText(failures)
}

private fun buildDnsttCopyText(
    resolvers: List<ResolverRecord>,
    e2eRequested: Boolean,
): String {
    val successfulResolvers = resolvers.onlySuccessfulDnsttResolvers(e2eRequested)
    if (successfulResolvers.isEmpty()) {
        return ""
    }
    return successfulResolvers.joinToString("\n") { it.ip }
}

private fun buildDnsttExportText(
    resolvers: List<ResolverRecord>,
    e2eRequested: Boolean,
): String {
    return buildDnsttCopyText(resolvers, e2eRequested)
}

private fun buildDnsttFailureCopyText(
    resolvers: List<ResolverRecord>,
    e2eRequested: Boolean,
): String {
    val failedResolvers = resolvers.onlyFailedDnsttResolvers(e2eRequested)
    if (failedResolvers.isEmpty()) {
        return ""
    }
    return failedResolvers.joinToString("\n") { it.ip }
}

private fun buildDnsttFailureExportText(
    resolvers: List<ResolverRecord>,
    e2eRequested: Boolean,
): String {
    return buildDnsttFailureCopyText(resolvers, e2eRequested)
}

private fun List<ResolverRecord>.onlySuccessfulDnsResolvers(): List<ResolverRecord> {
    return filter { resolver -> resolver.qualifiedForTunnel }
}

private fun List<ResolverRecord>.onlySuccessfulDnsttResolvers(
    e2eRequested: Boolean,
): List<ResolverRecord> {
    return filter { resolver ->
        if (e2eRequested) {
            resolver.dnsttE2eOk
        } else {
            resolver.dnsttTunnelOk
        }
    }
}

private fun List<ResolverRecord>.onlyFailedDnsttResolvers(
    e2eRequested: Boolean,
): List<ResolverRecord> {
    return filter { resolver ->
        resolver.dnsttChecked && (
            if (e2eRequested) {
                !resolver.dnsttE2eOk
            } else {
                !resolver.dnsttTunnelOk
            }
        )
    }
}

private fun compactFailureReason(reason: String): String {
    return reason
        .removePrefix("UDP probe failed: ")
        .removePrefix("TCP probe failed: ")
        .replace("IOException: Timed out while trying to resolve", "Timeout")
        .replace("java.net.SocketTimeoutException: ", "Timeout: ")
        .replace("DNS score", "Score")
        .replace('\n', ' ')
        .trim()
}

private fun exportFileName(prefix: String, extension: String = "txt"): String {
    val timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
    return "range-scout-$prefix-$timestamp.$extension"
}
