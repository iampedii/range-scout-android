package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.ScanConfigDraft
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanConfigValidatorTest {
    @Test
    fun validateAcceptsHostnamesAndUrls() {
        val config = ScanConfigValidator.validate(
            ScanConfigDraft(
                probeDomain = "https://github.com/login",
            ),
        ).getOrThrow()

        assertEquals("github.com", config.probeDomain)
    }

    @Test
    fun validateRejectsInvalidThreshold() {
        val result = ScanConfigValidator.validate(
            ScanConfigDraft(
                scoreThreshold = "9",
            ),
        )

        assertTrue(result.isFailure)
    }

    @Test
    fun validateCapsWorkersAtAndroidRuntimeLimit() {
        val config = ScanConfigValidator.validate(
            ScanConfigDraft(
                workers = "128",
            ),
        ).getOrThrow()

        assertEquals(64, config.workers)
    }

    @Test
    fun validateBoundsTimeoutForUsableDnsScans() {
        val lowConfig = ScanConfigValidator.validate(
            ScanConfigDraft(
                timeoutMillis = "50",
            ),
        ).getOrThrow()
        val highConfig = ScanConfigValidator.validate(
            ScanConfigDraft(
                timeoutMillis = "120000",
            ),
        ).getOrThrow()

        assertEquals(500, lowConfig.timeoutMillis)
        assertEquals(60000, highConfig.timeoutMillis)
    }
}
