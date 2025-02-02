import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wireguard/flutter_wireguard.dart';
import 'package:flutter_wireguard/flutter_wireguard_platform_interface.dart';
import 'package:flutter_wireguard/flutter_wireguard_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterWireguardPlatform
    with MockPlatformInterfaceMixin
    implements FlutterWireguardPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final FlutterWireguardPlatform initialPlatform = FlutterWireguardPlatform.instance;

  test('$MethodChannelFlutterWireguard is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterWireguard>());
  });

  test('getPlatformVersion', () async {
    FlutterWireguard flutterWireguardPlugin = FlutterWireguard();
    MockFlutterWireguardPlatform fakePlatform = MockFlutterWireguardPlatform();
    FlutterWireguardPlatform.instance = fakePlatform;

    expect(await flutterWireguardPlugin.getPlatformVersion(), '42');
  });
}
