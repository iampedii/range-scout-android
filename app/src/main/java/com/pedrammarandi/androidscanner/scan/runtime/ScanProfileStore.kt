package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft

data class ScannerProfile(
    val scanConfigDraft: ScanConfigDraft,
    val dnsttConfigDraft: DnsttConfigDraft,
)

fun interface ScanProfileStore {
    fun load(): ScannerProfile?

    fun save(profile: ScannerProfile) {
        // Optional for stores that support persistence.
    }
}

object NoOpScanProfileStore : ScanProfileStore {
    override fun load(): ScannerProfile? = null
}
