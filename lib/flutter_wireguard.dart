import 'package:flutter_wireguard/flutter_wireguard_platform_interface.dart';

class FlutterWireguard extends FlutterWireguardPlatformInterface {
  @override
  Future<void> start({required String name, required String config}) =>
      FlutterWireguardPlatformInterface.instance
          .start(name: name, config: config);

  @override
  Future<void> stop({required String name}) =>
      FlutterWireguardPlatformInterface.instance.stop(name: name);

  @override
  Future<dynamic> status({required String name}) =>
      FlutterWireguardPlatformInterface.instance.status(name: name);

  @override
  Future<Stream<dynamic>> statusStream() =>
      FlutterWireguardPlatformInterface.instance.statusStream();
}
