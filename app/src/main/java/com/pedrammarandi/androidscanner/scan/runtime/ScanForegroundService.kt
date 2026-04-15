package com.pedrammarandi.androidscanner.scan.runtime

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import com.pedrammarandi.androidscanner.AndroidScannerApplication
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class ScanForegroundService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var activeJob: kotlinx.coroutines.Job? = null
    private lateinit var repository: ScanRepository
    private lateinit var engine: ScanEngine
    private lateinit var dnsttRunner: DnsttRunner
    private lateinit var notifier: ScanNotifier
    private var scanNotificationWarningReported = false
    private var dnsttNotificationWarningReported = false
    private var scanProgressLogMark = 0L

    override fun onCreate() {
        super.onCreate()
        val app = application as AndroidScannerApplication
        repository = app.container.scanRepository
        engine = app.container.scanEngine
        dnsttRunner = app.container.dnsttRunner
        notifier = ScanNotifier(this)
        notifier.ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            actionStart -> startScan()
            actionStartDnstt -> startDnstt()
            actionCancel -> cancelScan()
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startScan() {
        if (activeJob?.isActive == true) {
            return
        }

        val request = repository.buildRuntimeRequest().getOrElse { error ->
            repository.markScanFailed(error.message ?: "Unable to build scan request.")
            stopSelf()
            return
        }

        if (!startForegroundSafely("Preparing scan runtime")) {
            repository.markScanFailed("Unable to start scan foreground service.")
            stopSelf()
            return
        }
        repository.markScanRunning(request)
        scanNotificationWarningReported = false
        scanProgressLogMark = 0L
        Log.i(logTag, "DNS scan started: targets=${request.totalTargets}, workers=${request.config.workers}")

        activeJob = serviceScope.launch {
            try {
                engine.run(request) { event ->
                    when (event) {
                        is ScanEvent.Progress -> {
                            repository.updateProgress(event.value)
                            logScanProgress(event.value.scanned, event.value.total)
                            runCatching {
                                notifier.notifyProgress(
                                    scanned = event.value.scanned,
                                    total = event.value.total,
                                )
                            }.onFailure {
                                if (scanNotificationWarningReported) {
                                    return@onFailure
                                }
                                scanNotificationWarningReported = true
                                repository.addWarning("Unable to update scan notification; scan is continuing")
                            }
                        }

                        is ScanEvent.ResolverFound -> repository.appendResolver(event.value)
                        is ScanEvent.ResolversFound -> repository.appendResolvers(event.values)
                        is ScanEvent.FailureRecorded -> repository.appendFailure(event.value)
                        is ScanEvent.FailuresRecorded -> repository.appendFailures(event.values)
                        is ScanEvent.Warning -> repository.addWarning(event.message)
                        ScanEvent.TransparentProxyDetected -> repository.markTransparentProxyDetected()
                    }
                }
                Log.i(logTag, "DNS scan completed")
                repository.markScanCompleted()
            } catch (_: CancellationException) {
                Log.i(logTag, "DNS scan cancelled")
                repository.markScanCancelled()
            } catch (error: Throwable) {
                Log.e(logTag, "DNS scan failed", error)
                repository.markScanFailed(error.message ?: "Unexpected scan failure.")
            } finally {
                activeJob = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun startDnstt() {
        if (activeJob?.isActive == true) {
            return
        }

        val request = repository.buildDnsttRuntimeRequest().getOrElse { error ->
            repository.markDnsttFailed(error.message ?: "Unable to build DNSTT request.")
            stopSelf()
            return
        }

        if (!startForegroundSafely("Preparing DNSTT runtime")) {
            repository.markDnsttFailed("Unable to start DNSTT foreground service.")
            stopSelf()
            return
        }
        repository.markDnsttRunning(request)
        dnsttNotificationWarningReported = false

        activeJob = serviceScope.launch {
            try {
                dnsttRunner.run(request) { event ->
                    when (event) {
                        is DnsttEvent.Progress -> {
                            repository.updateDnsttProgress(event.value)
                            runCatching {
                                notifier.notifyProgress(
                                    contentText = "DNSTT checked ${event.value.checked} of ${event.value.total} resolvers",
                                    progressCurrent = event.value.checked,
                                    progressTotal = event.value.total,
                                )
                            }.onFailure {
                                if (dnsttNotificationWarningReported) {
                                    return@onFailure
                                }
                                dnsttNotificationWarningReported = true
                                repository.addWarning("Unable to update DNSTT notification; scan is continuing")
                            }
                        }

                        is DnsttEvent.ResolverChecked -> repository.upsertDnsttResolver(event.value)
                    }
                }
                repository.markDnsttCompleted()
            } catch (_: CancellationException) {
                repository.markDnsttCancelled()
            } catch (error: Throwable) {
                repository.markDnsttFailed(error.message ?: "Unexpected DNSTT failure.")
            } finally {
                activeJob = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun cancelScan() {
        val job = activeJob
        if (job == null || !job.isActive) {
            stopSelf()
            return
        }
        job.cancel()
    }

    private fun startForegroundSafely(contentText: String): Boolean {
        return runCatching {
            startForeground(
                notifier.foregroundId(),
                notifier.buildPreparingNotification(contentText = contentText),
            )
        }.isSuccess
    }

    private fun logScanProgress(scanned: Long, total: Long) {
        val mark = scanned / 250L
        if (mark <= scanProgressLogMark && scanned < total) {
            return
        }
        scanProgressLogMark = mark
        Log.i(logTag, "DNS scan progress: scanned=$scanned total=$total")
    }

    companion object {
        private const val logTag = "ScanForegroundService"
        const val actionStart = "com.pedrammarandi.androidscanner.action.START_SCAN"
        const val actionStartDnstt = "com.pedrammarandi.androidscanner.action.START_DNSTT"
        const val actionCancel = "com.pedrammarandi.androidscanner.action.CANCEL_SCAN"
    }
}
