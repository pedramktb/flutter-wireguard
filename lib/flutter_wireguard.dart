
import 'flutter_wireguard_platform_interface.dart';

class FlutterWireguard {
  Future<String?> getPlatformVersion() {
    return FlutterWireguardPlatform.instance.getPlatformVersion();
  }
}
