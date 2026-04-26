/// flutter_wireguard public API.
///
/// All operations are top-level functions; there is no facade object to
/// instantiate. Status events are exposed as a single broadcast [Stream] that
/// any number of listeners can attach to.
library;

import 'dart:async';

import 'src/messages.g.dart';

export 'src/messages.g.dart'
    show TunnelStatus, TunnelState, BackendInfo, BackendKind;
export 'src/keys.dart';

final WireguardHostApi _host = WireguardHostApi();
final StreamController<TunnelStatus> _statusController =
    StreamController<TunnelStatus>.broadcast(
  onListen: _ensureFlutterApiRegistered,
);

bool _flutterApiRegistered = false;
void _ensureFlutterApiRegistered() {
  if (_flutterApiRegistered) return;
  WireguardFlutterApi.setUp(_FlutterApiAdapter(_statusController));
  _flutterApiRegistered = true;
}

class _FlutterApiAdapter implements WireguardFlutterApi {
  _FlutterApiAdapter(this._sink);
  final StreamController<TunnelStatus> _sink;
  @override
  void onTunnelStatus(TunnelStatus status) {
    if (!_sink.isClosed) _sink.add(status);
  }
}

/// Bring tunnel [name] up using the supplied wg-quick / wg-config string.
///
/// Throws [PlatformException] if the backend rejects the config or fails to
/// establish the tunnel.
Future<void> start(String name, String config) => _host.start(name, config);

/// Bring tunnel [name] down. No-op if it is already down or unknown.
Future<void> stop(String name) => _host.stop(name);

/// Snapshot of [name]'s current state and traffic counters.
Future<TunnelStatus> status(String name) => _host.status(name);

/// Names of every tunnel known to the backend in this process lifetime.
Future<List<String>> tunnelNames() => _host.tunnelNames();

/// Identifies the active backend (e.g. kernel vs userspace).
Future<BackendInfo> backend() => _host.backend();

/// Live status updates pushed by the platform side.
///
/// The stream is broadcast and lazily registers the underlying platform
/// receiver on first subscription.
Stream<TunnelStatus> statusStream() => _statusController.stream;
