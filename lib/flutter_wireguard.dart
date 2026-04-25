import 'package:flutter_wireguard/flutter_wireguard_platform_interface.dart';

@pragma('vm:entry-point')
class FlutterWireguard extends FlutterWireguardPlatformInterface {
  @override
  @pragma('vm:entry-point')
  Future<void> start({required String name, required String config}) =>
      FlutterWireguardPlatformInterface.instance
          .start(name: name, config: config);

  @override
  @pragma('vm:entry-point')
  Future<void> stop({required String name}) =>
      FlutterWireguardPlatformInterface.instance.stop(name: name);

  @override
  @pragma('vm:entry-point')
  Future<Map<String, dynamic>> status({required String name}) =>
      FlutterWireguardPlatformInterface.instance.status(name: name);

  @override
  @pragma('vm:entry-point')
  Stream<Map<String, dynamic>> statusStream() =>
      FlutterWireguardPlatformInterface.instance.statusStream();

  @override
  Future<String> backendType() =>
      FlutterWireguardPlatformInterface.instance.backendType();
}
