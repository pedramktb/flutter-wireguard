#ifndef FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_
#define FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_

#include <flutter/plugin_registrar_windows.h>

#include <memory>

#include "messages.g.h"

namespace flutter_wireguard {

class FlutterWireguardPlugin : public flutter::Plugin, public WireguardHostApi {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  FlutterWireguardPlugin(flutter::BinaryMessenger* messenger);
  ~FlutterWireguardPlugin() override;

  FlutterWireguardPlugin(const FlutterWireguardPlugin&) = delete;
  FlutterWireguardPlugin& operator=(const FlutterWireguardPlugin&) = delete;

  // WireguardHostApi
  void Start(const std::string& name, const std::string& config,
             std::function<void(std::optional<FlutterError> reply)> result)
      override;
  void Stop(const std::string& name,
            std::function<void(std::optional<FlutterError> reply)> result)
      override;
  void Status(const std::string& name,
              std::function<void(ErrorOr<TunnelStatus> reply)> result) override;
  void TunnelNames(
      std::function<void(ErrorOr<flutter::EncodableList> reply)> result)
      override;
  void Backend(
      std::function<void(ErrorOr<BackendInfo> reply)> result) override;

 private:
  void DispatchEvent(TunnelStatus status);

  std::unique_ptr<WireguardFlutterApi> flutter_api_;
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_PLUGIN_FLUTTER_WIREGUARD_PLUGIN_H_
