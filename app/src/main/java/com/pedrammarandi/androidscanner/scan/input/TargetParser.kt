package com.pedrammarandi.androidscanner.scan.input

import com.pedrammarandi.androidscanner.scan.model.PrefixEntry

private const val importedAsnLabel = "IMPORT"

data class TargetParseResult(
    val entries: List<PrefixEntry>,
    val totalAddresses: Long,
    val totalScanHosts: Long,
    val warnings: List<String>,
    val errorMessage: String? = null,
)

class TargetParser {
    fun parse(rawInput: String): TargetParseResult {
        val warnings = mutableListOf<String>()
        val merged = linkedMapOf<String, Ipv4Prefix>()

        rawInput.lineSequence().forEachIndexed { index, rawLine ->
            val line = normalizeLine(rawLine)
            if (line.isEmpty()) {
                return@forEachIndexed
            }

            val target = try {
                Ipv4Math.parseTarget(line)
            } catch (_: IllegalArgumentException) {
                warnings += "line ${index + 1}: invalid target \"$line\""
                return@forEachIndexed
            }

            merged[target.normalizedString()] = target
        }

        if (merged.isEmpty()) {
            return TargetParseResult(
                entries = emptyList(),
                totalAddresses = 0,
                totalScanHosts = 0,
                warnings = warnings,
                errorMessage = "No valid IPv4 ranges or single IPs found.",
            )
        }

        val sortedPrefixes = merged.values.sortedWith(
            compareBy<Ipv4Prefix> { it.maskedBaseAddress }.thenBy { it.prefixLength },
        )

        var totalAddresses = 0L
        var totalScanHosts = 0L
        val entries = sortedPrefixes.map { prefix ->
            val addressCount = prefix.addressCount()
            val scanHosts = prefix.usableHostCount()
            totalAddresses += addressCount
            totalScanHosts += scanHosts
            PrefixEntry(
                prefix = prefix.normalizedString(),
                sourceLabel = importedAsnLabel,
                sourceAsns = listOf(importedAsnLabel),
                totalAddresses = addressCount,
                scanHosts = scanHosts,
            )
        }

        return TargetParseResult(
            entries = entries,
            totalAddresses = totalAddresses,
            totalScanHosts = totalScanHosts,
            warnings = warnings,
        )
    }

    private fun normalizeLine(rawLine: String): String {
        val withoutComment = rawLine.substringBefore('#')
        return withoutComment.trim()
    }
}

