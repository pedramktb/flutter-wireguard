import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_wireguard_method_channel.dart';

abstract class FlutterWireguardPlatform extends PlatformInterface {
  /// Constructs a FlutterWireguardPlatform.
  FlutterWireguardPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterWireguardPlatform _instance = MethodChannelFlutterWireguard();

  /// The default instance of [FlutterWireguardPlatform] to use.
  ///
  /// Defaults to [MethodChannelFlutterWireguard].
  static FlutterWireguardPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [FlutterWireguardPlatform] when
  /// they register themselves.
  static set instance(FlutterWireguardPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
