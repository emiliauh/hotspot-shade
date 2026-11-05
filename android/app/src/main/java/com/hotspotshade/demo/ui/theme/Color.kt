package com.hotspotshade.demo.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

@Immutable
data class HsTokens(
    val success: Color,
    val warning: Color,
    val danger: Color,
    val info: Color,
    val statusOff: Color,
    val secondaryText: Color,
    val tertiaryFill: Color,
    val segmentIndicator: Color,
    val separator: Color,
    val cardTop: Color,
    val cardBottom: Color,
    val cardBorder: Color,
    val bannerSurface: Color,
    val bannerBorder: Color,
    val bannerText: Color,
    val chipSurface: Color,
    val chipBorder: Color,
    val scrim: Color,
)

val LightTokens = HsTokens(
    success = Color(0xFF248A3D),
    warning = Color(0xFFB25000),
    danger = Color(0xFFD70015),
    info = Color(0xFF007AFF),
    statusOff = Color(0xFF8E8E93),
    secondaryText = Color(0xFF6C6C70),
    tertiaryFill = Color(0xFFE9E9EE),
    segmentIndicator = Color(0xFFFFFFFF),
    separator = Color(0x2E3C3C43),
    cardTop = Color(0xFFFFFFFF),
    cardBottom = Color(0xFFFAFAFC),
    cardBorder = Color(0xFFE2E2E7),
    bannerSurface = Color(0xFFEAF3FF),
    bannerBorder = Color(0xFFB9D8FF),
    bannerText = Color(0xFF0B3D91),
    chipSurface = Color(0x14007AFF),
    chipBorder = Color(0x33007AFF),
    scrim = Color(0x66000000),
)

val DarkTokens = HsTokens(
    success = Color(0xFF30D158),
    warning = Color(0xFFFF9F0A),
    danger = Color(0xFFFF453A),
    info = Color(0xFF0A84FF),
    statusOff = Color(0xFF8E8E93),
    secondaryText = Color(0xFFAEAEB2),
    tertiaryFill = Color(0xFF2C2C2E),
    segmentIndicator = Color(0xFF3A3A3C),
    separator = Color(0x3D545458),
    cardTop = Color(0xFF2A2A2D),
    cardBottom = Color(0xFF1C1C1E),
    cardBorder = Color(0x1FFFFFFF),
    bannerSurface = Color(0xFF0B1B2E),
    bannerBorder = Color(0xFF1F4A7A),
    bannerText = Color(0xFF9CC9FF),
    chipSurface = Color(0x260A84FF),
    chipBorder = Color(0x4D0A84FF),
    scrim = Color(0x99000000),
)

val LocalHsTokens = staticCompositionLocalOf { LightTokens }
val LocalReduceMotion = staticCompositionLocalOf { false }
