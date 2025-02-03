import 'package:flutter_wireguard/flutter_wireguard_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

abstract class FlutterWireguardPlatformInterface extends PlatformInterface {
  FlutterWireguardPlatformInterface() : super(token: _token);

  static final Object _token = Object();

  static FlutterWireguardPlatformInterface _instance =
      FlutterWireguardMethodChannel();
  static FlutterWireguardPlatformInterface get instance => _instance;
  static set instance(FlutterWireguardPlatformInterface instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<void> start({
    required String name,
    required String config,
  }) async =>
      throw UnimplementedError();

  Future<void> stop({required String name}) async => throw UnimplementedError();

  Future<Stream<dynamic>> status() async => throw UnimplementedError();
}
