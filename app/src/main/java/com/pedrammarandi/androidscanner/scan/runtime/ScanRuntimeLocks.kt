package com.pedrammarandi.androidscanner.scan.runtime

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import android.os.PowerManager
import android.util.Log

class ScanRuntimeLocks(
    context: Context,
) {
    private val appContext = context.applicationContext
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    @SuppressLint("WakelockTimeout")
    fun acquire(): List<String> {
        val warnings = mutableListOf<String>()

        runCatching {
            val lock = wakeLock ?: createWakeLock().also { wakeLock = it }
            if (!lock.isHeld) {
                lock.acquire()
            }
        }.onFailure { error ->
            Log.w(logTag, "Unable to acquire scan wake lock", error)
            warnings += "Unable to keep CPU awake while locked; scan will continue but may pause if the device sleeps."
        }

        runCatching {
            val lock = wifiLock ?: createWifiLock().also { wifiLock = it }
            if (!lock.isHeld) {
                lock.acquire()
            }
        }.onFailure { error ->
            Log.w(logTag, "Unable to acquire scan Wi-Fi lock", error)
            warnings += "Unable to keep Wi-Fi awake while locked; scan will continue but network speed may drop."
        }

        return warnings
    }

    fun release() {
        releaseWifiLock()
        releaseWakeLock()
    }

    private fun createWakeLock(): PowerManager.WakeLock {
        val powerManager = appContext.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: error("Power service unavailable.")
        return powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$lockTag:Cpu").apply {
            setReferenceCounted(false)
        }
    }

    private fun createWifiLock(): WifiManager.WifiLock {
        val wifiManager = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: error("Wi-Fi service unavailable.")
        return wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "$lockTag:Wifi").apply {
            setReferenceCounted(false)
        }
    }

    private fun releaseWakeLock() {
        runCatching {
            wakeLock?.takeIf { it.isHeld }?.release()
        }.onFailure { error ->
            Log.w(logTag, "Unable to release scan wake lock", error)
        }
    }

    private fun releaseWifiLock() {
        runCatching {
            wifiLock?.takeIf { it.isHeld }?.release()
        }.onFailure { error ->
            Log.w(logTag, "Unable to release scan Wi-Fi lock", error)
        }
    }

    private companion object {
        private const val logTag = "ScanRuntimeLocks"
        private const val lockTag = "AndroidScanner:ScanRuntime"
    }
}
