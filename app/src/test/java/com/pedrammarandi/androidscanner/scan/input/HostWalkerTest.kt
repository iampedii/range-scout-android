package com.pedrammarandi.androidscanner.scan.input

import com.pedrammarandi.androidscanner.scan.model.PrefixEntry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class HostWalkerTest {
    private val hostWalker = HostWalker()

    @Test
    fun walkSkipsNetworkAndBroadcastForStandardCidrs() = runBlocking {
        val visited = mutableListOf<String>()

        hostWalker.walk(
            entries = listOf(
                PrefixEntry(
                    prefix = "203.0.113.0/30",
                    sourceLabel = "IMPORT",
                    sourceAsns = listOf("IMPORT"),
                    totalAddresses = 4,
                    scanHosts = 2,
                ),
            ),
        ) { address, _ ->
            visited += address
            true
        }

        assertEquals(listOf("203.0.113.1", "203.0.113.2"), visited)
    }

    @Test
    fun walkIncludesAllAddressesForSlash31AndSlash32() = runBlocking {
        val visited = mutableListOf<String>()

        hostWalker.walk(
            entries = listOf(
                PrefixEntry(
                    prefix = "198.51.100.10/31",
                    sourceLabel = "IMPORT",
                    sourceAsns = listOf("IMPORT"),
                    totalAddresses = 2,
                    scanHosts = 2,
                ),
                PrefixEntry(
                    prefix = "198.51.100.20/32",
                    sourceLabel = "IMPORT",
                    sourceAsns = listOf("IMPORT"),
                    totalAddresses = 1,
                    scanHosts = 1,
                ),
            ),
        ) { address, _ ->
            visited += address
            true
        }

        assertEquals(
            listOf("198.51.100.10", "198.51.100.11", "198.51.100.20"),
            visited,
        )
    }
}

