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

using namespace flutter;
using namespace std;

namespace flutter_wireguard
{

  // static
  void FlutterWireguardPlugin::RegisterWithRegistrar(PluginRegistrarWindows *registrar)
  {
    auto channel = make_unique<MethodChannel<EncodableValue>>(
        registrar->messenger(), "dev.fluttercommunity.flutter_wireguard/methodChannel", &StandardMethodCodec::GetInstance());
    auto eventChannel = make_unique<EventChannel<EncodableValue>>(
        registrar->messenger(), "dev.fluttercommunity.flutter_wireguard/eventChannel", &StandardMethodCodec::GetInstance());

    auto plugin = make_unique<FlutterWireguardPlugin>();

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

  FlutterWireguardPlugin::FlutterWireguardPlugin() {}

  FlutterWireguardPlugin::~FlutterWireguardPlugin() {}

  void FlutterWireguardPlugin::HandleMethodCall(const MethodCall<EncodableValue> &call,
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

      long long tx = 0, rx = 0;

      flutter::EncodableMap map = {{flutter::EncodableValue("name"), flutter::EncodableValue(WideToAnsi(this->tunnel_service_->service_name_))},
                                   {flutter::EncodableValue("state"), flutter::EncodableValue(state)},
                                   {flutter::EncodableValue("tx"), flutter::EncodableValue(tx)},
                                   {flutter::EncodableValue("rx"), flutter::EncodableValue(rx)}};
      result->Success(flutter::EncodableValue(map));
      return;
    }

    result->NotImplemented();
  }

  unique_ptr<StreamHandlerError<EncodableValue>> FlutterWireguardPlugin::OnListen(
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

  unique_ptr<StreamHandlerError<EncodableValue>> FlutterWireguardPlugin::OnCancel(
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
