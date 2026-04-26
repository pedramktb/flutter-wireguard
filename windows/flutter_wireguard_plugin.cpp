#include "flutter_wireguard_plugin.h"

#include <windows.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>

#include "../cpp/name_validator.h"
#include "broker_client.h"
#include "messages.g.h"

namespace flutter_wireguard {

namespace {

// Cross-thread dispatcher: status callbacks fire on the BrokerClient reader
// thread, but BinaryMessenger is engine-thread-affine. We park each event on a
// hidden HWND_MESSAGE window and post WM_USER; the platform thread's message
// loop drains the queue and calls WireguardFlutterApi::OnTunnelStatus.
class StatusDispatcher {
 public:
  static constexpr UINT kWmDrain = WM_USER + 1;

  StatusDispatcher(flutter::BinaryMessenger* messenger,
                   std::unique_ptr<WireguardFlutterApi> api)
      : api_(std::move(api)) {
    (void)messenger;
    static std::once_flag once;
    std::call_once(once, []() {
      WNDCLASSW wc{};
      wc.lpfnWndProc = &StatusDispatcher::WndProc;
      wc.hInstance = ::GetModuleHandleW(nullptr);
      wc.lpszClassName = L"FlutterWireguardDispatcher";
      ::RegisterClassW(&wc);
    });
    hwnd_ = ::CreateWindowExW(0, L"FlutterWireguardDispatcher", nullptr, 0, 0,
                              0, 0, 0, HWND_MESSAGE, nullptr,
                              ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd_ != nullptr) {
      ::SetWindowLongPtrW(hwnd_, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(this));
    }
  }

  ~StatusDispatcher() {
    if (hwnd_ != nullptr) ::DestroyWindow(hwnd_);
  }

  void Post(BrokerStatus s) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      queue_.push(std::move(s));
    }
    if (hwnd_ != nullptr) ::PostMessage(hwnd_, kWmDrain, 0, 0);
  }

 private:
  static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == kWmDrain) {
      auto* self = reinterpret_cast<StatusDispatcher*>(
          ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
      if (self != nullptr) self->Drain();
      return 0;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
  }

  void Drain() {
    std::queue<BrokerStatus> local;
    {
      std::lock_guard<std::mutex> lock(mu_);
      std::swap(local, queue_);
    }
    while (!local.empty()) {
      const auto& s = local.front();
      TunnelStatus st(s.name,
                      s.state == 2 ? TunnelState::kUp
                                    : (s.state == 1 ? TunnelState::kToggle
                                                    : TunnelState::kDown),
                      s.rx, s.tx, s.handshake_ms);
      api_->OnTunnelStatus(st, [] {}, [](const FlutterError&) {});
      local.pop();
    }
  }

  std::unique_ptr<WireguardFlutterApi> api_;
  HWND hwnd_ = nullptr;
  std::mutex mu_;
  std::queue<BrokerStatus> queue_;
};

std::unique_ptr<StatusDispatcher>& Dispatcher() {
  static std::unique_ptr<StatusDispatcher> d;
  return d;
}

}  // namespace

// static
void FlutterWireguardPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto plugin = std::make_unique<FlutterWireguardPlugin>(registrar->messenger());
  WireguardHostApi::SetUp(registrar->messenger(), plugin.get());
  registrar->AddPlugin(std::move(plugin));
}

FlutterWireguardPlugin::FlutterWireguardPlugin(
    flutter::BinaryMessenger* messenger) {
  auto api = std::make_unique<WireguardFlutterApi>(messenger);
  Dispatcher() = std::make_unique<StatusDispatcher>(messenger, std::move(api));

  BrokerClient::Instance().SetStatusCallback([](const BrokerStatus& s) {
    if (auto& d = Dispatcher()) d->Post(s);
  });
}

FlutterWireguardPlugin::~FlutterWireguardPlugin() {
  BrokerClient::Instance().SetStatusCallback({});
  Dispatcher().reset();
}

void FlutterWireguardPlugin::Start(
    const std::string& name, const std::string& config,
    std::function<void(std::optional<FlutterError> reply)> result) {
  if (!IsValidTunnelName(name)) {
    result(FlutterError("START_FAILED", "invalid tunnel name"));
    return;
  }
  // Run on a worker thread: launching the broker (UAC + pipe handshake) can
  // block several seconds.
  std::thread([name, config, result = std::move(result)]() mutable {
    try {
      BrokerClient::Instance().Start(name, config);
      result(std::nullopt);
    } catch (const std::exception& e) {
      result(FlutterError("START_FAILED", e.what()));
    }
  }).detach();
}

void FlutterWireguardPlugin::Stop(
    const std::string& name,
    std::function<void(std::optional<FlutterError> reply)> result) {
  if (!IsValidTunnelName(name)) {
    result(FlutterError("STOP_FAILED", "invalid tunnel name"));
    return;
  }
  std::thread([name, result = std::move(result)]() mutable {
    try {
      BrokerClient::Instance().Stop(name);
      result(std::nullopt);
    } catch (const std::exception& e) {
      result(FlutterError("STOP_FAILED", e.what()));
    }
  }).detach();
}

void FlutterWireguardPlugin::Status(
    const std::string& name,
    std::function<void(ErrorOr<TunnelStatus> reply)> result) {
  if (!IsValidTunnelName(name)) {
    result(FlutterError("STATUS_FAILED", "invalid tunnel name"));
    return;
  }
  std::thread([name, result = std::move(result)]() mutable {
    try {
      BrokerStatus s = BrokerClient::Instance().Status(name);
      TunnelStatus st(s.name,
                      s.state == 2 ? TunnelState::kUp
                                    : (s.state == 1 ? TunnelState::kToggle
                                                    : TunnelState::kDown),
                      s.rx, s.tx, s.handshake_ms);
      result(st);
    } catch (const std::exception& e) {
      result(FlutterError("STATUS_FAILED", e.what()));
    }
  }).detach();
}

void FlutterWireguardPlugin::TunnelNames(
    std::function<void(ErrorOr<flutter::EncodableList> reply)> result) {
  std::thread([result = std::move(result)]() mutable {
    try {
      auto names = BrokerClient::Instance().TunnelNames();
      flutter::EncodableList out;
      out.reserve(names.size());
      for (auto& n : names) out.emplace_back(n);
      result(out);
    } catch (const std::exception& e) {
      result(FlutterError("LIST_FAILED", e.what()));
    }
  }).detach();
}

void FlutterWireguardPlugin::Backend(
    std::function<void(ErrorOr<BackendInfo> reply)> result) {
  std::thread([result = std::move(result)]() mutable {
    try {
      BrokerBackend b = BrokerClient::Instance().Backend();
      BackendKind kind = BackendKind::kUnknown;
      if (b.kind == 0) kind = BackendKind::kKernel;
      else if (b.kind == 1) kind = BackendKind::kUserspace;
      result(BackendInfo(kind, b.detail));
    } catch (const std::exception& e) {
      result(FlutterError("BACKEND_FAILED", e.what()));
    }
  }).detach();
}

}  // namespace flutter_wireguard
