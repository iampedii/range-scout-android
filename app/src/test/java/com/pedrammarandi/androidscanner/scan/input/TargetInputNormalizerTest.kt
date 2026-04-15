package com.pedrammarandi.androidscanner.scan.input

import java.io.StringReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TargetInputNormalizerTest {
    @Test
    fun normalizeImportedTargetsSplitsCommaSeparatedTargetsIntoLines() {
        val normalized = TargetInputNormalizer.normalizeImportedTargets(
            "1.1.1.1, 2.2.2.2/24\n3.3.3.3",
        )

        assertEquals(
            "1.1.1.1\n2.2.2.2/24\n3.3.3.3",
            normalized,
        )
    }

    @Test
    fun normalizeImportedTargetsTrimsBlankLinesAndBom() {
        val normalized = TargetInputNormalizer.normalizeImportedTargets(
            "\uFEFF\n 1.1.1.1 \n\n, 2.2.2.2 ",
        )

        assertEquals(
            "1.1.1.1\n2.2.2.2",
            normalized,
        )
    }

    @Test
    fun normalizeImportedTargetsStreamsReaderAndCountsTargets() {
        val normalized = TargetInputNormalizer.normalizeImportedTargets(
            reader = StringReader("1.1.1.1,2.2.2.2\n3.3.3.3"),
        )

        assertEquals(3, normalized.targetCount)
        assertEquals(
            "1.1.1.1\n2.2.2.2\n3.3.3.3",
            normalized.text,
        )
    }

    @Test
    fun normalizeImportedTargetsRejectsTooManyTargets() {
        assertThrows(IllegalArgumentException::class.java) {
            TargetInputNormalizer.normalizeImportedTargets(
                reader = StringReader("1.1.1.1\n2.2.2.2"),
                maxTargets = 1,
            )
        }
    }
}
