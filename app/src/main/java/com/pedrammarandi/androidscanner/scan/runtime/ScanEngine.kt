package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.FailureRecord
import com.pedrammarandi.androidscanner.scan.model.ResolverRecord
import com.pedrammarandi.androidscanner.scan.model.ScanProgress
import com.pedrammarandi.androidscanner.scan.model.ScanRuntimeRequest

sealed interface ScanEvent {
    data class Progress(val value: ScanProgress) : ScanEvent
    data class ResolverFound(val value: ResolverRecord) : ScanEvent
    data class ResolversFound(val values: List<ResolverRecord>) : ScanEvent
    data class FailureRecorded(val value: FailureRecord) : ScanEvent
    data class FailuresRecorded(val values: List<FailureRecord>) : ScanEvent
    data class Warning(val message: String) : ScanEvent
    data object TransparentProxyDetected : ScanEvent
}

fun interface ScanEngine {
    suspend fun run(
        request: ScanRuntimeRequest,
        emit: suspend (ScanEvent) -> Unit,
    )
}
