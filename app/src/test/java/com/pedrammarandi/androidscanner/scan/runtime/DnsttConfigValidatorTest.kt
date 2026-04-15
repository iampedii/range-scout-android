package com.pedrammarandi.androidscanner.scan.runtime

import com.pedrammarandi.androidscanner.scan.model.DnsttConfigDraft
import com.pedrammarandi.androidscanner.scan.model.DnsttTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsttConfigValidatorTest {
    @Test
    fun validateAllowsTunnelOnlyWithoutPubkey() {
        val result = DnsttConfigValidator.validate(
            DnsttConfigDraft(
                workers = "6",
                timeoutMillis = "3500",
                transport = DnsttTransport.TCP,
                domain = "Resolver.EXAMPLE.",
                pubkey = "",
                e2eTimeoutSeconds = "25",
            ),
        )

        assertTrue(result.isSuccess)
        val config = result.getOrThrow()
        assertEquals(6, config.workers)
        assertEquals(3500, config.timeoutMillis)
        assertEquals(DnsttTransport.TCP, config.transport)
        assertEquals("resolver.example", config.domain)
        assertEquals("", config.pubkey)
    }

    @Test
    fun validateRejectsSocksPasswordWithoutUsername() {
        val result = DnsttConfigValidator.validate(
            DnsttConfigDraft(
                pubkey = "deadbeef",
                socksPassword = "secret",
            ),
        )

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message.orEmpty().contains("SOCKS username"))
    }

    @Test
    fun validateRejectsInvalidHttpUrlWhenE2eEnabled() {
        val result = DnsttConfigValidator.validate(
            DnsttConfigDraft(
                pubkey = "deadbeef",
                e2eUrl = "not-a-url",
            ),
        )

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message.orEmpty().contains("http or https"))
    }
}
