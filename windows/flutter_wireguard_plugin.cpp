#include "flutter_wireguard_plugin.h"

// This must be included before many other Windows headers.
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/encodable_value.h>
#include <libbase64.h>
#include <windows.h>

#include <memory>
#include <sstream>

#include "config_writer.h"
#include "service_control.h"
#include "utils.h"
#include "wireguard.h"

using namespace flutter;
using namespace std;

namespace flutter_wireguard
{

  namespace
  {
    const unsigned long long WINDOWS_TO_UNIX_EPOCH_100NS = 116444736000000000ULL; // 1601->1970 offset

    inline long long filetime100nsToUnixMs(unsigned long long ticks100ns)
    {
      if (ticks100ns == 0 || ticks100ns < WINDOWS_TO_UNIX_EPOCH_100NS)
      {
        return 0;
      }
      return static_cast<long long>((ticks100ns - WINDOWS_TO_UNIX_EPOCH_100NS) / 10000ULL);
    }

    struct WireGuardApi
    {
      HMODULE module = nullptr;
      WIREGUARD_OPEN_ADAPTER_FUNC *OpenAdapter = nullptr;
      WIREGUARD_GET_CONFIGURATION_FUNC *GetConfiguration = nullptr;
      WIREGUARD_CLOSE_ADAPTER_FUNC *CloseAdapter = nullptr;
    };

    inline bool LoadWireGuardApi(WireGuardApi &api)
    {
      if (api.module != nullptr)
      {
        return api.OpenAdapter && api.GetConfiguration && api.CloseAdapter;
      }

      api.module = LoadLibraryW(L"wireguard.dll");
      if (!api.module)
      {
        return false;
      }

      api.OpenAdapter = reinterpret_cast<WIREGUARD_OPEN_ADAPTER_FUNC *>(GetProcAddress(api.module, "WireGuardOpenAdapter"));
      api.GetConfiguration = reinterpret_cast<WIREGUARD_GET_CONFIGURATION_FUNC *>(GetProcAddress(api.module, "WireGuardGetConfiguration"));
      api.CloseAdapter = reinterpret_cast<WIREGUARD_CLOSE_ADAPTER_FUNC *>(GetProcAddress(api.module, "WireGuardCloseAdapter"));

      return api.OpenAdapter && api.GetConfiguration && api.CloseAdapter;
    }

    inline bool QueryWireGuardStats(const std::wstring &adapter_name, long long &out_rx, long long &out_tx, long long &out_handshake_ms)
    {
      out_rx = 0;
      out_tx = 0;
      out_handshake_ms = 0;

      WireGuardApi api;
      if (!LoadWireGuardApi(api))
      {
        return false;
      }

      WIREGUARD_ADAPTER_HANDLE adapter = api.OpenAdapter(adapter_name.c_str());
      if (adapter == NULL)
      {
        return false;
      }

      // First attempt with a reasonable buffer, then grow if needed
      DWORD alloc_bytes = sizeof(WIREGUARD_INTERFACE) + 64 * 1024;
      std::vector<unsigned char> buffer(alloc_bytes);
      DWORD bytes = alloc_bytes;

      BOOL ok = api.GetConfiguration(adapter, reinterpret_cast<WIREGUARD_INTERFACE *>(buffer.data()), &bytes);
      if (!ok && GetLastError() == ERROR_MORE_DATA)
      {
        buffer.resize(bytes);
        ok = api.GetConfiguration(adapter, reinterpret_cast<WIREGUARD_INTERFACE *>(buffer.data()), &bytes);
      }

      if (!ok)
      {
        api.CloseAdapter(adapter);
        return false;
      }

      auto *config = reinterpret_cast<WIREGUARD_INTERFACE *>(buffer.data());

      unsigned char *cursor = reinterpret_cast<unsigned char *>(config) + sizeof(WIREGUARD_INTERFACE);
      unsigned long long max_handshake_100ns = 0ULL;
      unsigned long long sum_rx = 0ULL;
      unsigned long long sum_tx = 0ULL;

      for (DWORD i = 0; i < config->PeersCount; ++i)
      {
        auto *peer = reinterpret_cast<WIREGUARD_PEER *>(cursor);
        sum_tx += peer->TxBytes;
        sum_rx += peer->RxBytes;
        if (peer->LastHandshake > max_handshake_100ns)
        {
          max_handshake_100ns = peer->LastHandshake;
        }
        cursor += sizeof(WIREGUARD_PEER) + peer->AllowedIPsCount * sizeof(WIREGUARD_ALLOWED_IP);
      }

      out_rx = static_cast<long long>(sum_rx);
      out_tx = static_cast<long long>(sum_tx);
      out_handshake_ms = filetime100nsToUnixMs(max_handshake_100ns);

      api.CloseAdapter(adapter);
      return true;
    }
  } // namespace

  // static
  void WireguardFlutterPlugin::RegisterWithRegistrar(PluginRegistrarWindows *registrar)
  {
    auto channel = make_unique<MethodChannel<EncodableValue>>(
        registrar->messenger(), "dev.fluttercommunity.flutter_wireguard/methodChannel", &StandardMethodCodec::GetInstance());
    auto eventChannel = make_unique<EventChannel<EncodableValue>>(
        registrar->messenger(), "dev.fluttercommunity.flutter_wireguard/eventChannel", &StandardMethodCodec::GetInstance());

    auto plugin = make_unique<WireguardFlutterPlugin>();

    channel->SetMethodCallHandler([plugin_pointer = plugin.get()](const auto &call, auto result)
                                  { plugin_pointer->HandleMethodCall(call, move(result)); });

    auto eventsHandler = make_unique<StreamHandlerFunctions<EncodableValue>>(
        [plugin_pointer = plugin.get()](
            const EncodableValue *arguments,
            unique_ptr<EventSink<EncodableValue>> &&events)
            -> unique_ptr<StreamHandlerError<EncodableValue>>
        {
          return plugin_pointer->OnListen(arguments, move(events));
        },
        [plugin_pointer = plugin.get()](const EncodableValue *arguments)
            -> unique_ptr<StreamHandlerError<EncodableValue>>
        {
          return plugin_pointer->OnCancel(arguments);
        });

    eventChannel->SetStreamHandler(move(eventsHandler));

    registrar->AddPlugin(move(plugin));
  }

  WireguardFlutterPlugin::WireguardFlutterPlugin() {}

  WireguardFlutterPlugin::~WireguardFlutterPlugin() {}

  void WireguardFlutterPlugin::HandleMethodCall(const MethodCall<EncodableValue> &call,
                                                unique_ptr<MethodResult<EncodableValue>> result)
  {
    const auto *args = get_if<EncodableMap>(call.arguments());

    if (call.method_name() == "start")
    {
      auto tunnel_service = this->tunnel_service_.get();
      if (tunnel_service == nullptr)
      {
        const auto *name = get_if<string>(ValueOrNull(*args, "name"));
        if (name == NULL)
        {
          result->Error("Argument 'name' is required");
          return;
        }
        if (this->tunnel_service_ != nullptr)
        {
          this->tunnel_service_->service_name_ = Utf8ToWide(*name);
        }
        else
        {
          this->tunnel_service_ = make_unique<ServiceControl>(Utf8ToWide(*name));
          this->tunnel_service_->RegisterListener(move(events_));
        }

        tunnel_service = this->tunnel_service_.get();
      }

      const auto *config = get_if<string>(ValueOrNull(*args, "config"));
      if (config == NULL)
      {
        result->Error("Argument 'config' is required");
        return;
      }

      wstring wg_config_filename;
      try
      {
        wg_config_filename = WriteConfigToTempFile(*config);
      }
      catch (exception &e)
      {
        result->Error(string("Could not write wireguard config: ").append(e.what()));
        return;
      }

      wchar_t module_filename[MAX_PATH];
      GetModuleFileName(NULL, module_filename, MAX_PATH);
      auto current_exec_dir = wstring(module_filename);
      current_exec_dir = current_exec_dir.substr(0, current_exec_dir.find_last_of(L"\\/"));
      wostringstream service_exec_builder;
      service_exec_builder << current_exec_dir << "\\wireguard_svc.exe" << L" -service"
                           << L" -config-file=\"" << wg_config_filename << "\"";
      wstring service_exec = service_exec_builder.str();
      cout << "Starting service with command line: " << WideToAnsi(service_exec) << endl;
      try
      {
        CreateArgs csa;
        csa.description = tunnel_service->service_name_ + L" WireGuard tunnel";
        csa.executable_and_args = service_exec;
        csa.dependencies = L"Nsi\0TcpIp\0";
        csa.first_time = true;

        tunnel_service->CreateAndStart(csa);
      }
      catch (exception &e)
      {
        result->Error(string(e.what()));
        return;
      }

      result->Success();
      return;
    }
    else if (call.method_name() == "stop")
    {
      auto tunnel_service = this->tunnel_service_.get();
      if (tunnel_service == nullptr)
      {
        const auto *name = get_if<string>(ValueOrNull(*args, "name"));
        if (name == NULL)
        {
          result->Error("Argument 'name' is required");
          return;
        }
        if (this->tunnel_service_ != nullptr)
        {
          this->tunnel_service_->service_name_ = Utf8ToWide(*name);
        }
        else
        {
          this->tunnel_service_ = make_unique<ServiceControl>(Utf8ToWide(*name));
          this->tunnel_service_->RegisterListener(move(events_));
        }

        tunnel_service = this->tunnel_service_.get();
      }

      try
      {
        tunnel_service->Stop();
      }
      catch (exception &e)
      {
        result->Error(string(e.what()));
      }

      result->Success();
      return;
    }
    else if (call.method_name() == "status")
    {
      auto tunnel_service = this->tunnel_service_.get();
      if (tunnel_service == nullptr)
      {
        const auto *name = get_if<string>(ValueOrNull(*args, "name"));
        if (name == NULL)
        {
          result->Error("Argument 'name' is required");
          return;
        }
        if (this->tunnel_service_ != nullptr)
        {
          this->tunnel_service_->service_name_ = Utf8ToWide(*name);
        }
        else
        {
          this->tunnel_service_ = make_unique<ServiceControl>(Utf8ToWide(*name));
          this->tunnel_service_->RegisterListener(move(events_));
        }

        tunnel_service = this->tunnel_service_.get();
      }

      string state = tunnel_service->GetStatus() == "connected" ? "UP" : "DOWN";

      long long tx = 0, rx = 0, handshake = 0;

      // Try to read real-time statistics from the WireGuard driver
      try
      {
        if (name != nullptr)
        {
          std::wstring adapter_name = Utf8ToWide(*name);
          QueryWireGuardStats(adapter_name, rx, tx, handshake);
        }
      }
      catch (...)
      {
        // Best-effort; leave zeros on failure
      }

      flutter::EncodableMap map = {{flutter::EncodableValue("name"), flutter::EncodableValue(name)},
                                   {flutter::EncodableValue("state"), flutter::EncodableValue(state)},
                                   {flutter::EncodableValue("tx"), flutter::EncodableValue(tx)},
                                   {flutter::EncodableValue("rx"), flutter::EncodableValue(rx)},
                                   {flutter::EncodableValue("handshake"), flutter::EncodableValue(handshake)}};
      result->Success(flutter::EncodableValue(map));
      return;
    }

    result->NotImplemented();
  }

  unique_ptr<StreamHandlerError<EncodableValue>> WireguardFlutterPlugin::OnListen(
      const EncodableValue *arguments,
      unique_ptr<EventSink<EncodableValue>> &&events)
  {
    events_ = move(events);
    auto tunnel_service = this->tunnel_service_.get();
    if (tunnel_service != nullptr)
    {
      tunnel_service->RegisterListener(move(events_));
      return nullptr;
    }

    return nullptr;
  }

  unique_ptr<StreamHandlerError<EncodableValue>> WireguardFlutterPlugin::OnCancel(
      const EncodableValue *arguments)
  {
    events_ = nullptr;
    auto tunnel_service = this->tunnel_service_.get();
    if (tunnel_service != nullptr)
    {
      tunnel_service->UnregisterListener();
      return nullptr;
    }

    return nullptr;
  }

} // namespace flutter_wireguard
