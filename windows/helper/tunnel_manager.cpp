#include "tunnel_manager.h"

#include <windows.h>
#include <winsvc.h>

#include <chrono>
#include <map>
#include <sstream>
#include <stdexcept>

#include "../utils.h"
#include "config_writer.h"
#include "wireguard_dll.h"

namespace flutter_wireguard {

namespace {

constexpr wchar_t kServicePrefix[] = L"WireGuardTunnel$";
// Best-effort timeout for SCM start/stop transitions (ms).
constexpr DWORD kTransitionTimeoutMs = 15'000;

std::wstring ServiceName(const std::string& tunnel_name) {
  return std::wstring(kServicePrefix) + Utf8ToWide(tunnel_name);
}

class ScopedScm {
 public:
  ScopedScm(DWORD access) {
    h_ = ::OpenSCManagerW(nullptr, nullptr, access);
    if (h_ == nullptr) {
      throw std::runtime_error(
          ErrorWithCode("OpenSCManager", ::GetLastError()));
    }
  }
  ~ScopedScm() {
    if (h_ != nullptr) ::CloseServiceHandle(h_);
  }
  ScopedScm(const ScopedScm&) = delete;
  ScopedScm& operator=(const ScopedScm&) = delete;
  SC_HANDLE get() const { return h_; }

 private:
  SC_HANDLE h_ = nullptr;
};

class ScopedService {
 public:
  ScopedService(SC_HANDLE h) : h_(h) {}
  ~ScopedService() {
    if (h_ != nullptr) ::CloseServiceHandle(h_);
  }
  ScopedService(const ScopedService&) = delete;
  ScopedService& operator=(const ScopedService&) = delete;
  operator bool() const { return h_ != nullptr; }
  SC_HANDLE get() const { return h_; }

 private:
  SC_HANDLE h_ = nullptr;
};

DWORD QueryState(SC_HANDLE service) {
  SERVICE_STATUS_PROCESS s{};
  DWORD needed = 0;
  if (!::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&s),
                              sizeof(s), &needed)) {
    return 0;
  }
  return s.dwCurrentState;
}

uint8_t MapServiceState(DWORD scm_state) {
  switch (scm_state) {
    case SERVICE_RUNNING:
      return 2;  // up
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
      return 1;  // toggle
    default:
      return 0;  // down (incl. SERVICE_STOPPED, 0)
  }
}

void DeleteServiceIfExists(const std::wstring& service_name) {
  ScopedScm scm(SC_MANAGER_CONNECT);
  ScopedService svc(::OpenServiceW(scm.get(), service_name.c_str(),
                                   SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS));
  if (!svc) return;
  DWORD state = QueryState(svc.get());
  if (state == SERVICE_RUNNING || state == SERVICE_START_PENDING) {
    SERVICE_STATUS s{};
    ::ControlService(svc.get(), SERVICE_CONTROL_STOP, &s);
    auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(kTransitionTimeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
      DWORD cur = QueryState(svc.get());
      if (cur == SERVICE_STOPPED || cur == 0) break;
      ::Sleep(200);
    }
  }
  ::DeleteService(svc.get());
}

}  // namespace

TunnelManager::TunnelManager(std::wstring helper_path)
    : helper_path_(std::move(helper_path)) {}

TunnelManager::~TunnelManager() { Shutdown(); }

void TunnelManager::Shutdown() {
  stop_.store(true);
  if (poller_.joinable()) poller_.join();
}

void TunnelManager::SetStatusCallback(StatusCallback cb) {
  std::lock_guard<std::mutex> lock(mu_);
  callback_ = std::move(cb);
  EnsurePollerStarted();
}

void TunnelManager::EnsurePollerStarted() {
  if (poller_.joinable()) return;
  stop_.store(false);
  poller_ = std::thread(&TunnelManager::PollLoop, this);
}

void TunnelManager::Start(const std::string& name, const std::string& config) {
  std::wstring wname = Utf8ToWide(name);
  std::wstring service_name = ServiceName(name);

  // 1) Persist encrypted config + plaintext for tunnel.dll.
  std::wstring dpapi_path = SecureConfigStore::WriteEncrypted(wname, config);
  std::wstring conf_path = SecureConfigStore::WritePlaintext(wname, config);

  // 2) (Re)create the service.
  DeleteServiceIfExists(service_name);

  std::wostringstream cmd;
  cmd << L'"' << helper_path_ << L"\" --tunnel-service \"" << conf_path << L'"';
  std::wstring cmdline = cmd.str();

  ScopedScm scm(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
  ScopedService svc(::CreateServiceW(
      scm.get(), service_name.c_str(), service_name.c_str(),
      SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL, cmdline.c_str(), nullptr, nullptr,
      L"Nsi\0TcpIp\0\0", nullptr /* LocalSystem */, nullptr));
  if (!svc) {
    DWORD err = ::GetLastError();
    SecureConfigStore::Erase(wname);
    throw std::runtime_error(ErrorWithCode("CreateService", err));
  }

  SERVICE_SID_INFO sid_info{SERVICE_SID_TYPE_UNRESTRICTED};
  ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_SERVICE_SID_INFO,
                          &sid_info);

  std::wstring desc_w = service_name + L" - WireGuard tunnel managed by flutter_wireguard";
  std::vector<wchar_t> desc_buf(desc_w.begin(), desc_w.end());
  desc_buf.push_back(L'\0');
  SERVICE_DESCRIPTION desc{desc_buf.data()};
  ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

  if (!::StartServiceW(svc.get(), 0, nullptr)) {
    DWORD err = ::GetLastError();
    if (err != ERROR_SERVICE_ALREADY_RUNNING) {
      ::DeleteService(svc.get());
      SecureConfigStore::Erase(wname);
      throw std::runtime_error(ErrorWithCode("StartService", err));
    }
  }

  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(kTransitionTimeoutMs);
  while (std::chrono::steady_clock::now() < deadline) {
    DWORD cur = QueryState(svc.get());
    if (cur == SERVICE_RUNNING) break;
    if (cur == SERVICE_STOPPED || cur == 0) {
      // Service died during startup. Pull the latest exit code if we can.
      SERVICE_STATUS_PROCESS s{};
      DWORD needed = 0;
      ::QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<BYTE*>(&s), sizeof(s), &needed);
      DWORD exit_code = s.dwWin32ExitCode != 0 ? s.dwWin32ExitCode
                                                : s.dwServiceSpecificExitCode;
      ::DeleteService(svc.get());
      SecureConfigStore::Erase(wname);
      throw std::runtime_error(
          ErrorWithCode("tunnel service exited during startup", exit_code));
    }
    ::Sleep(200);
  }

  std::lock_guard<std::mutex> lock(mu_);
  known_tunnels_.insert(name);
  EnsurePollerStarted();
}

void TunnelManager::Stop(const std::string& name) {
  std::wstring service_name = ServiceName(name);
  DeleteServiceIfExists(service_name);
  SecureConfigStore::Erase(Utf8ToWide(name));
  std::lock_guard<std::mutex> lock(mu_);
  // Keep it in known_tunnels_ so subsequent Status() succeeds and reports DOWN.
  known_tunnels_.insert(name);
}

TunnelStatusSnapshot TunnelManager::QueryStatusUnlocked(
    const std::string& name) {
  TunnelStatusSnapshot s;
  s.name = name;

  ScopedScm scm(SC_MANAGER_CONNECT);
  ScopedService svc(::OpenServiceW(scm.get(), ServiceName(name).c_str(),
                                   SERVICE_QUERY_STATUS));
  if (!svc) {
    s.state = 0;
    return s;
  }
  s.state = MapServiceState(QueryState(svc.get()));

  if (s.state == 2) {
    WireGuardStats stats;
    if (WireGuardDll::Instance().QueryStats(Utf8ToWide(name), &stats)) {
      s.rx = stats.rx;
      s.tx = stats.tx;
      s.handshake_ms = stats.handshake_ms;
    }
  }
  return s;
}

TunnelStatusSnapshot TunnelManager::Status(const std::string& name) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (known_tunnels_.find(name) == known_tunnels_.end()) {
      throw std::runtime_error("unknown tunnel '" + name + "'");
    }
  }
  return QueryStatusUnlocked(name);
}

std::vector<std::string> TunnelManager::TunnelNames() const {
  std::lock_guard<std::mutex> lock(mu_);
  return {known_tunnels_.begin(), known_tunnels_.end()};
}

BackendInfoSnapshot TunnelManager::Backend() const {
  BackendInfoSnapshot b;
  b.kind = 1;  // userspace
  b.detail = "wireguard-nt + tunnel.dll";
  return b;
}

void TunnelManager::PollLoop() {
  std::map<std::string, uint8_t> last_state;
  while (!stop_.load()) {
    std::vector<std::string> names;
    StatusCallback cb;
    {
      std::lock_guard<std::mutex> lock(mu_);
      names.assign(known_tunnels_.begin(), known_tunnels_.end());
      cb = callback_;
    }
    if (cb) {
      for (const auto& n : names) {
        TunnelStatusSnapshot s = QueryStatusUnlocked(n);
        bool changed = last_state[n] != s.state;
        last_state[n] = s.state;
        // Always emit while UP for stats ticks; otherwise only on change.
        if (changed || s.state == 2) cb(s);
      }
    }
    for (int i = 0; i < 10 && !stop_.load(); ++i) ::Sleep(100);
  }
}

}  // namespace flutter_wireguard
