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

  final Exception invalidStatus = Exception("Invalid status response");

  @override
  Future<dynamic> status({required String name}) async =>
      _methodChannel.invokeMethod("status", {
        "name": name,
      }).then((value) => value is Map<String, dynamic>
          ? {
              "name":
                  value["name"] is String ? value["name"] : throw invalidStatus,
              "state": value["state"] is String
                  ? value["state"]
                  : throw invalidStatus,
              "rx": value["rx"] is int ? value["rx"] : throw invalidStatus,
              "tx": value["tx"] is int ? value["tx"] : throw invalidStatus,
            }
          : throw invalidStatus);

  @override
  Future<Stream<dynamic>> statusStream() async => _eventChannel
      .receiveBroadcastStream()
      .map((event) => event is Map<String, dynamic>
          ? {
              "name":
                  event["name"] is String ? event["name"] : throw invalidStatus,
              "state": event["state"] is String
                  ? event["state"]
                  : throw invalidStatus,
              "rx": event["rx"] is int ? event["rx"] : throw invalidStatus,
              "tx": event["tx"] is int ? event["tx"] : throw invalidStatus,
            }
          : throw invalidStatus);
}
