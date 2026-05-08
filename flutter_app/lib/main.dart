// lib/main.dart
//
// clicksafe — ML-powered phishing detection mobile app.
// Entry point: initialises Flutter, applies the dark theme, and launches HomeScreen.
//
// FIX-04 (Memory Leak — http.Client Singleton Never Closed):
//   clicksafeApp is now a StatefulWidget that mixes in WidgetsBindingObserver.
//   didChangeAppLifecycleState() calls ApiService.instance.dispose() when the
//   OS signals AppLifecycleState.detached (the app is being torn down).
//   This closes the persistent http.Client, releasing all open TCP connections
//   and preventing socket accumulation.
//
//   Why StatefulWidget instead of StatelessWidget:
//   • WidgetsBindingObserver must be registered/unregistered via initState()
//     and dispose() — both are StatefulWidget lifecycle hooks.
//   • The StatelessWidget build() method is unsuitable for one-time setup.
//
//   The app's visual structure and theme are completely unchanged.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'theme/app_theme.dart';
import 'screens/home_screen.dart';
import 'services/api_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // Force portrait orientation — the app is designed for portrait layout.
  SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Use a dark system UI overlay style to match the app's dark theme.
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor:                    Colors.transparent,
    statusBarIconBrightness:           Brightness.light,
    systemNavigationBarColor:          AppTheme.bgPrimary,
    systemNavigationBarIconBrightness: Brightness.light,
  ));

  runApp(const clicksafeApp());
}

// FIX-04: Changed from StatelessWidget → StatefulWidget + WidgetsBindingObserver
// so we can hook into the app lifecycle and close the HTTP client on detach.
class clicksafeApp extends StatefulWidget {
  const clicksafeApp({super.key});

  @override
  State<clicksafeApp> createState() => _clicksafeAppState();
}

class _clicksafeAppState extends State<clicksafeApp>
    with WidgetsBindingObserver {

  @override
  void initState() {
    super.initState();
    // Register this widget as a lifecycle observer so didChangeAppLifecycleState
    // is called whenever the OS changes the app's lifecycle state.
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    // Unregister the observer when the widget is removed from the tree.
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// Called by the Flutter framework when the OS changes the app lifecycle.
  ///
  /// AppLifecycleState.detached is triggered when the app is being fully
  /// torn down (killed by the OS or by the user closing it).  This is the
  /// correct place to release long-lived resources such as HTTP clients.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.detached) {
      // FIX-04: Close the singleton http.Client to release all open sockets.
      ApiService.instance.dispose();
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title:                      'clicksafe',
      debugShowCheckedModeBanner: false,
      theme:                      AppTheme.dark,
      home:                       const HomeScreen(),
    );
  }
}
