package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.input.HostWalker
import com.pedrammarandi.androidscanner.scan.model.ScanProgress
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive

private const val previewHostCap = 4096L
private const val previewChunkSize = 128L

class PreviewScanEngine(
    private val hostWalker: HostWalker,
) : ScanEngine {
    override suspend fun run(
        request: com.pedrammarandi.androidscanner.scan.model.ScanRuntimeRequest,
        emit: suspend (ScanEvent) -> Unit,
    ) {
        emit(
            ScanEvent.Warning(
                "Foreground service wiring is live. DNS transport probes are the next porting step.",
            ),
        )

        val effectiveTargetLimit = minOf(request.totalTargets, previewHostCap)
        if (request.totalTargets > effectiveTargetLimit) {
            emit(
                ScanEvent.Warning(
                    "Preview mode capped the host walk at $effectiveTargetLimit out of ${request.totalTargets} targets.",
                ),
            )
        }

        var scanned = 0L
        emit(ScanEvent.Progress(ScanProgress(total = effectiveTargetLimit)))

        hostWalker.walk(request.targets, effectiveTargetLimit) { _, _ ->
            currentCoroutineContext().ensureActive()
            scanned += 1

            if (scanned == effectiveTargetLimit || scanned % previewChunkSize == 0L) {
                emit(
                    ScanEvent.Progress(
                        ScanProgress(
                            scanned = scanned,
                            total = effectiveTargetLimit,
                            working = 0,
                            compatible = 0,
                            qualified = 0,
                        ),
                    ),
                )
                delay(20)
            }

            true
        }

        emit(
            ScanEvent.Progress(
                ScanProgress(
                    scanned = scanned,
                    total = effectiveTargetLimit,
                    working = 0,
                    compatible = 0,
                    qualified = 0,
                ),
            ),
        )
    }
}

