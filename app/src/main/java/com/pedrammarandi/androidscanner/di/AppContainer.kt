package com.pedrammarandi.androidscanner.di

import android.content.Context
import com.pedrammarandi.androidscanner.scan.input.HostWalker
import com.pedrammarandi.androidscanner.scan.input.TargetParser
import com.pedrammarandi.androidscanner.scan.runtime.DnsScanEngine
import com.pedrammarandi.androidscanner.scan.runtime.GoDnsttRunner
import com.pedrammarandi.androidscanner.scan.runtime.ScanController
import com.pedrammarandi.androidscanner.scan.runtime.SharedPreferencesScanProfileStore
import com.pedrammarandi.androidscanner.scan.runtime.ScanRepository

class AppContainer(appContext: Context) {
    private val targetParser = TargetParser()
    private val hostWalker = HostWalker()
    private val profileStore = SharedPreferencesScanProfileStore(appContext)

    val scanRepository = ScanRepository(
        targetParser = targetParser,
        profileStore = profileStore,
    )
    val scanController = ScanController(appContext)
    val scanEngine = DnsScanEngine(hostWalker = hostWalker)
    val dnsttRunner = GoDnsttRunner(context = appContext)
}
