package com.pedrammarandi.androidscanner.scan.input

internal data class Ipv4Prefix(
    val baseAddress: Long,
    val prefixLength: Int,
) {
    init {
        require(prefixLength in 0..32) { "prefixLength must be between 0 and 32" }
    }

    val maskedBaseAddress: Long = Ipv4Math.maskAddress(baseAddress, prefixLength)

    fun normalizedString(): String = "${Ipv4Math.formatAddress(maskedBaseAddress)}/$prefixLength"

    fun addressCount(): Long = 1L shl (32 - prefixLength)

    fun usableHostCount(): Long {
        val total = addressCount()
        return if (prefixLength < 31 && total >= 2) total - 2 else total
    }

    fun hostBounds(): LongRange? {
        val total = addressCount()
        if (total <= 0) {
            return null
        }

        val start = if (prefixLength < 31 && total >= 2) maskedBaseAddress + 1 else maskedBaseAddress
        val end = if (prefixLength < 31 && total >= 2) maskedBaseAddress + total - 2 else maskedBaseAddress + total - 1
        return start..end
    }
}

internal object Ipv4Math {
    fun parseTarget(raw: String): Ipv4Prefix {
        val trimmed = raw.trim()
        return if (trimmed.contains('/')) parsePrefix(trimmed) else Ipv4Prefix(parseAddress(trimmed), 32)
    }

    fun parsePrefix(raw: String): Ipv4Prefix {
        val parts = raw.split('/')
        require(parts.size == 2) { "invalid target \"$raw\"" }
        val address = parseAddress(parts[0].trim())
        val prefixLength = parts[1].trim().toIntOrNull()
            ?: throw IllegalArgumentException("invalid target \"$raw\"")
        if (prefixLength !in 0..32) {
            throw IllegalArgumentException("invalid target \"$raw\"")
        }
        return Ipv4Prefix(address, prefixLength)
    }

    fun parseAddress(raw: String): Long {
        val octets = raw.split('.')
        require(octets.size == 4) { "invalid target \"$raw\"" }

        var value = 0L
        for (octet in octets) {
            if (octet.isBlank()) {
                throw IllegalArgumentException("invalid target \"$raw\"")
            }
            val parsed = octet.toIntOrNull() ?: throw IllegalArgumentException("invalid target \"$raw\"")
            if (parsed !in 0..255) {
                throw IllegalArgumentException("invalid target \"$raw\"")
            }
            value = (value shl 8) or parsed.toLong()
        }
        return value and 0xFFFF_FFFFL
    }

    fun formatAddress(raw: Long): String {
        return buildString {
            append((raw shr 24) and 0xFF)
            append('.')
            append((raw shr 16) and 0xFF)
            append('.')
            append((raw shr 8) and 0xFF)
            append('.')
            append(raw and 0xFF)
        }
    }

    fun maskAddress(raw: Long, prefixLength: Int): Long {
        if (prefixLength == 0) {
            return 0L
        }
        val shift = 32 - prefixLength
        val mask = ((0xFFFF_FFFFL shr shift) shl shift) and 0xFFFF_FFFFL
        return raw and mask
    }
}

