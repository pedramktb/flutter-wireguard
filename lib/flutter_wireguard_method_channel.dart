import 'package:flutter/services.dart';
import 'package:flutter_wireguard/flutter_wireguard_platform_interface.dart';

class FlutterWireguardMethodChannel extends FlutterWireguardPlatformInterface {
  static const _methodChannel =
      MethodChannel("dev.fluttercommunity.flutter_wireguard/methodChannel");
  static const _eventChannel =
      EventChannel('dev.fluttercommunity.flutter_wireguard/eventChannel');

  @override
  Future<void> start({
    required String name,
    required String config,
  }) async {
    return _methodChannel.invokeMethod("start", {
      "name": name,
      "config": config,
    });
  }

  @override
  Future<void> stop({
    required String name,
  }) async =>
      _methodChannel.invokeMethod('stop');

  @override
  Future<Stream<dynamic>> status() async =>
      _eventChannel.receiveBroadcastStream().map((event) => event as dynamic);
}
