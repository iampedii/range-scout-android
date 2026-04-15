package com.pedrammarandi.androidscanner.scan.input

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetParserTest {
    private val parser = TargetParser()

    @Test
    fun parseNormalizesSingleIpsCidrsAndComments() {
        val result = parser.parse(
            """
            # comment
            198.51.100.9
            198.51.100.42/24
            198.51.100.9
            invalid
            """.trimIndent(),
        )

        assertEquals(listOf("198.51.100.0/24", "198.51.100.9/32"), result.entries.map { it.prefix })
        assertEquals(257L, result.totalAddresses)
        assertEquals(255L, result.totalScanHosts)
        assertEquals(1, result.warnings.size)
    }

    @Test
    fun parseReturnsErrorWhenNothingValidExists() {
        val result = parser.parse(
            """
            bad
            # only comments
            """.trimIndent(),
        )

        assertTrue(result.entries.isEmpty())
        assertEquals("No valid IPv4 ranges or single IPs found.", result.errorMessage)
    }

    @Test
    fun parseHandlesMultipleSlash24InputsUsedForLargeDnsScan() {
        val result = parser.parse(
            """
            1.1.1.1/24
            2.2.2.2/24
            3.3.3.3/24
            4.4.4.4/24
            5.5.5.5/24
            8.8.8.8/24
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                "1.1.1.0/24",
                "2.2.2.0/24",
                "3.3.3.0/24",
                "4.4.4.0/24",
                "5.5.5.0/24",
                "8.8.8.0/24",
            ),
            result.entries.map { it.prefix },
        )
        assertEquals(1536L, result.totalAddresses)
        assertEquals(1524L, result.totalScanHosts)
        assertTrue(result.warnings.isEmpty())
    }
}
