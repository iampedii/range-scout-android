package com.pedrammarandi.androidscanner.scan.input

import java.io.Reader

object TargetInputNormalizer {
    const val defaultMaxImportedTargets = 100_000
    const val defaultMaxImportedCharacters = 2_000_000

    data class NormalizedTargets(
        val text: String,
        val targetCount: Int,
    )

    fun normalizeImportedTargets(rawInput: String): String {
        return normalizeImportedTargets(
            reader = rawInput.reader(),
            maxTargets = Int.MAX_VALUE,
            maxCharacters = Int.MAX_VALUE,
        ).text
    }

    fun normalizeImportedTargets(
        reader: Reader,
        maxTargets: Int = defaultMaxImportedTargets,
        maxCharacters: Int = defaultMaxImportedCharacters,
    ): NormalizedTargets {
        val normalized = StringBuilder()
        val token = StringBuilder()
        val buffer = CharArray(size = 8_192)
        var targetCount = 0

        fun flushToken() {
            val value = token.toString().trim()
            token.setLength(0)
            if (value.isEmpty()) {
                return
            }

            if (targetCount >= maxTargets) {
                throw IllegalArgumentException(
                    "Import file has more than $maxTargets targets. Split it into smaller files.",
                )
            }

            val separatorLength = if (normalized.isEmpty()) 0 else 1
            if (normalized.length + separatorLength + value.length > maxCharacters) {
                throw IllegalArgumentException(
                    "Import file is too large to display. Split it into smaller files.",
                )
            }

            if (normalized.isNotEmpty()) {
                normalized.append('\n')
            }
            normalized.append(value)
            targetCount++
        }

        while (true) {
            val read = reader.read(buffer)
            if (read < 0) {
                break
            }

            for (index in 0 until read) {
                when (val char = buffer[index]) {
                    '\uFEFF' -> Unit
                    ',', '\n', '\r' -> flushToken()
                    else -> {
                        token.append(char)
                        if (token.length > maxCharacters) {
                            throw IllegalArgumentException(
                                "Import file is too large to display. Split it into smaller files.",
                            )
                        }
                    }
                }
            }
        }

        flushToken()
        return NormalizedTargets(
            text = normalized.toString(),
            targetCount = targetCount,
        )
    }
}
    
