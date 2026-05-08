// lib/theme/app_theme.dart

import 'package:flutter/material.dart';

class AppTheme {
  AppTheme._();

  // ── Brand colours ──────────────────────────────────────────────────────────
  static const Color bgPrimary    = Color(0xFF0A0F1E);   // deep navy
  static const Color bgSecondary  = Color(0xFF111827);   // dark slate
  static const Color bgCard       = Color(0xFF1F2937);   // card surface
  static const Color bgCardBorder = Color(0xFF374151);   // subtle border

  static const Color accentBlue   = Color(0xFF3B82F6);   // primary action
  static const Color accentCyan   = Color(0xFF06B6D4);   // highlights
  static const Color accentPurple = Color(0xFF8B5CF6);   // ML / AI elements

  static const Color textPrimary   = Color(0xFFF9FAFB);
  static const Color textSecondary = Color(0xFF9CA3AF);
  static const Color textMuted     = Color(0xFF6B7280);

  static const Color safeGreen    = Color(0xFF22C55E);
  static const Color warnAmber    = Color(0xFFF59E0B);
  static const Color dangerRed    = Color(0xFFEF4444);

  // ── Text styles ────────────────────────────────────────────────────────────
  static const TextStyle headingLarge = TextStyle(
    fontSize: 28,
    fontWeight: FontWeight.w800,
    color: textPrimary,
    letterSpacing: -0.5,
  );

  static const TextStyle headingMedium = TextStyle(
    fontSize: 20,
    fontWeight: FontWeight.w700,
    color: textPrimary,
  );

  static const TextStyle bodyText = TextStyle(
    fontSize: 14,
    color: textSecondary,
    height: 1.5,
  );

  static const TextStyle labelSmall = TextStyle(
    fontSize: 12,
    color: textMuted,
    letterSpacing: 0.5,
  );

  static const TextStyle monoUrl = TextStyle(
    fontSize: 13,
    fontFamily: 'monospace',
    color: accentCyan,
  );

  // ── Theme data ─────────────────────────────────────────────────────────────
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: bgPrimary,
    colorScheme: const ColorScheme.dark(
      primary:   accentBlue,
      secondary: accentCyan,
      surface:   bgSecondary,
      error:     dangerRed,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: bgPrimary,
      foregroundColor: textPrimary,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        fontSize: 18,
        fontWeight: FontWeight.w700,
        color: textPrimary,
      ),
    ),
    cardTheme: CardThemeData(
      color: bgCard,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: bgCardBorder, width: 1),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: bgCard,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: bgCardBorder),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: bgCardBorder),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: accentBlue, width: 2),
      ),
      hintStyle: const TextStyle(color: textMuted),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: accentBlue,
        foregroundColor: Colors.white,
        elevation: 0,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
      ),
    ),
    chipTheme: ChipThemeData(
      backgroundColor: bgCard,
      labelStyle: const TextStyle(color: textSecondary, fontSize: 12),
      side: const BorderSide(color: bgCardBorder),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    ),
    dividerTheme: const DividerThemeData(color: bgCardBorder, thickness: 1),
    textTheme: const TextTheme(
      bodyLarge:   TextStyle(color: textPrimary, fontSize: 16),
      bodyMedium:  TextStyle(color: textSecondary, fontSize: 14),
      bodySmall:   TextStyle(color: textMuted, fontSize: 12),
      labelLarge:  TextStyle(color: textPrimary, fontWeight: FontWeight.w600),
    ),
  );
}
