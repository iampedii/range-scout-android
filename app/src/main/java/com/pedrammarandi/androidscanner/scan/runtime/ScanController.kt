package com.pedrammarandi.androidscanner.scan.runtime

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

class ScanController(
    private val appContext: Context,
) {
    fun start() {
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, ScanForegroundService::class.java).setAction(ScanForegroundService.actionStart),
        )
    }

    fun startDnstt() {
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, ScanForegroundService::class.java).setAction(ScanForegroundService.actionStartDnstt),
        )
    }

    fun cancel() {
        appContext.startService(
            Intent(appContext, ScanForegroundService::class.java).setAction(ScanForegroundService.actionCancel),
        )
    }
}
