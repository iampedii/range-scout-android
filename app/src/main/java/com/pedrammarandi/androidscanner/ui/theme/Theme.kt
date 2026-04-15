package com.pedrammarandi.androidscanner.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColors = darkColorScheme(
    primary = NeonBlue,
    onPrimary = PrimaryForeground,
    primaryContainer = MutedSurface,
    onPrimaryContainer = TextPrimary,
    secondary = ElectricPurple,
    onSecondary = TextPrimary,
    secondaryContainer = MutedSurface,
    onSecondaryContainer = TextPrimary,
    tertiary = AccentCyan,
    onTertiary = PrimaryForeground,
    error = ErrorPink,
    onError = PrimaryForeground,
    background = DeepSpace,
    onBackground = TextPrimary,
    surface = CardSurface,
    onSurface = TextPrimary,
    surfaceVariant = MutedSurface,
    onSurfaceVariant = TextSecondary,
    outline = BorderGlow,
    outlineVariant = BorderGlow,
)

@Composable
fun AndroidScannerTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = Typography,
        content = content,
    )
}
