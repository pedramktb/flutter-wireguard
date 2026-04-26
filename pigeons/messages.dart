// Pigeon API definition for flutter_wireguard.
//
// Regenerate stubs with:
//   dart run pigeon --input pigeons/messages.dart
//
// All Dart-side code lives under lib/src/messages.g.dart, Kotlin under
// android/.../Messages.g.kt, and C++ under linux/messages.g.{h,cc}.
import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/src/messages.g.dart',
  dartOptions: DartOptions(),
  kotlinOut:
      'android/src/main/kotlin/com/pedramktb/flutter_wireguard/Messages.g.kt',
  kotlinOptions: KotlinOptions(
    package: 'com.pedramktb.flutter_wireguard',
  ),
  gobjectHeaderOut: 'linux/messages.g.h',
  gobjectSourceOut: 'linux/messages.g.cc',
  gobjectOptions: GObjectOptions(),
  dartPackageName: 'flutter_wireguard',
))

/// Tunnel runtime state. Mirrors com.wireguard.android.backend.Tunnel.State.
enum TunnelState { down, toggle, up }

/// A snapshot of a tunnel's runtime status.
class TunnelStatus {
  TunnelStatus({
    required this.name,
    required this.state,
    required this.rx,
    required this.tx,
    required this.handshake,
  });

  /// Tunnel/interface name (e.g. "wg0").
  final String name;

  /// Current state.
  final TunnelState state;

  /// Total bytes received across all peers.
  final int rx;

  /// Total bytes transmitted across all peers.
  final int tx;

  /// Latest handshake epoch milliseconds (0 if none yet).
  final int handshake;
}

/// Identifies which underlying engine is in use.
enum BackendKind {
  /// Linux kernel WireGuard module (via wg-quick).
  kernel,

  /// Userspace implementation: wireguard-go on Android, or
  /// wireguard-go / boringtun on Linux (via wg-quick env var).
  userspace,

  /// Backend not initialised yet (or unavailable).
  unknown,
}

class BackendInfo {
  BackendInfo({required this.kind, required this.detail});

  final BackendKind kind;

  /// Free-form description (e.g. "GoBackend", "WgQuickBackend (kernel)",
  /// "wg-quick + wireguard-go").
  final String detail;
}

/// Host -> platform calls. All implementations must be reentrant and may be
/// called from any isolate / thread.
@HostApi()
abstract class WireguardHostApi {
  /// Bring the tunnel up with the given wg-quick / wg-config string.
  /// Throws [PlatformException] with code "START_FAILED" on backend failure.
  @async
  void start(String name, String config);

  /// Bring the named tunnel down. No-op if already down.
  @async
  void stop(String name);

  /// Returns the current status. Throws if the tunnel was never started.
  @async
  TunnelStatus status(String name);

  /// Returns the names of all currently-known tunnels (including DOWN ones
  /// that were started in this process lifetime).
  @async
  List<String> tunnelNames();

  /// Returns the active backend.
  @async
  BackendInfo backend();
}

/// Platform -> host events.
@FlutterApi()
abstract class WireguardFlutterApi {
  /// Pushed whenever a tunnel changes state or its statistics tick.
  void onTunnelStatus(TunnelStatus status);
}
