#if os(iOS)
import Flutter
import UIKit
#elseif os(macOS)
import FlutterMacOS
import Cocoa
#endif

public class FlutterWireguardPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(iOS)
    let messenger = registrar.messenger()
    #else
    let messenger = registrar.messenger
    #endif
    let channel = FlutterMethodChannel(name: "flutter_wireguard", binaryMessenger: messenger)
    let instance = FlutterWireguardPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getPlatformVersion":
      #if os(iOS)
      result("iOS " + UIDevice.current.systemVersion)
      #elseif os(macOS)
      result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
      #endif
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}

// macOS registrant expects `WireguardFlutterPlugin` per pubspec.yaml.
// Provide a forwarding class to keep iOS/macOS shared source working.
public class WireguardFlutterPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    FlutterWireguardPlugin.register(with: registrar)
  }
}
