#ifndef FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_
#define FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace flutter_wireguard {

class FlutterWireguardPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  FlutterWireguardPlugin();

  virtual ~FlutterWireguardPlugin();

  // Disallow copy and assign.
  FlutterWireguardPlugin(const FlutterWireguardPlugin&) = delete;
  FlutterWireguardPlugin& operator=(const FlutterWireguardPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_
