import 'package:flutter_wireguard/flutter_wireguard_platform_interface.dart';

class FlutterWireguard {
  static Future<void> start({
    required String name,
    required String config,
  }) async {
    return FlutterWireguardPlatformInterface.instance.start(
      name: name,
      config: config,
    );
  }

  static Future<void> stop({
    required String name,
  }) async {
    return FlutterWireguardPlatformInterface.instance.stop(
      name: name,
    );
  }

  static Future<Stream<dynamic>> status() async {
    return FlutterWireguardPlatformInterface.instance.status();
  }
}
