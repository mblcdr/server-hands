package com.samsaz.serverhands.ui

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * Material 3 scheme from an amber seed (hue ~40). Roles follow the standard tonal palettes: primary tone 40/80,
 * containers 90/30, secondary a desaturated amber, tertiary an olive green that stays apart from the primary, and
 * neutrals tinted warm.
 */
val AmberLight: ColorScheme = lightColorScheme(
    primary = Color(0xFF825500), onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFFFDDB3), onPrimaryContainer = Color(0xFF291800),
    secondary = Color(0xFF6F5B40), onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFFBDEBC), onSecondaryContainer = Color(0xFF271904),
    tertiary = Color(0xFF51643F), onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFD4EABB), onTertiaryContainer = Color(0xFF102004),
    error = Color(0xFFBA1A1A), onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF410002),
    background = Color(0xFFFFF8F4), onBackground = Color(0xFF201B13),
    surface = Color(0xFFFFF8F4), onSurface = Color(0xFF201B13),
    surfaceVariant = Color(0xFFF0E0CF), onSurfaceVariant = Color(0xFF4F4539),
    outline = Color(0xFF817567), outlineVariant = Color(0xFFD3C4B4),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFF362F27), inverseOnSurface = Color(0xFFFBEEDF), inversePrimary = Color(0xFFFFB951),
    surfaceTint = Color(0xFF825500),
    surfaceDim = Color(0xFFE3D8CC), surfaceBright = Color(0xFFFFF8F4),
    surfaceContainerLowest = Color(0xFFFFFFFF), surfaceContainerLow = Color(0xFFFEF2E4),
    surfaceContainer = Color(0xFFF8ECDD), surfaceContainerHigh = Color(0xFFF2E6D7), surfaceContainerHighest = Color(0xFFECE0D2),
)

val AmberDark: ColorScheme = darkColorScheme(
    primary = Color(0xFFFFB951), onPrimary = Color(0xFF452B00),
    primaryContainer = Color(0xFF633F00), onPrimaryContainer = Color(0xFFFFDDB3),
    secondary = Color(0xFFDDC2A1), onSecondary = Color(0xFF3E2D16),
    secondaryContainer = Color(0xFF56442A), onSecondaryContainer = Color(0xFFFBDEBC),
    tertiary = Color(0xFFB8CEA1), onTertiary = Color(0xFF243515),
    tertiaryContainer = Color(0xFF3A4C2A), onTertiaryContainer = Color(0xFFD4EABB),
    error = Color(0xFFFFB4AB), onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF17130B), onBackground = Color(0xFFEBE1D4),
    surface = Color(0xFF17130B), onSurface = Color(0xFFEBE1D4),
    surfaceVariant = Color(0xFF4F4539), onSurfaceVariant = Color(0xFFD3C4B4),
    outline = Color(0xFF9C8F80), outlineVariant = Color(0xFF4F4539),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFFEBE1D4), inverseOnSurface = Color(0xFF362F27), inversePrimary = Color(0xFF825500),
    surfaceTint = Color(0xFFFFB951),
    surfaceDim = Color(0xFF17130B), surfaceBright = Color(0xFF3E382F),
    surfaceContainerLowest = Color(0xFF120D07), surfaceContainerLow = Color(0xFF201B13),
    surfaceContainer = Color(0xFF241F17), surfaceContainerHigh = Color(0xFF2F2921), surfaceContainerHighest = Color(0xFF3A342B),
)
