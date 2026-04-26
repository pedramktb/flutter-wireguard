#include "broker_client.h"

#include <shellapi.h>
#include <windows.h>
#include <wtsapi32.h>

#include <chrono>
#include <stdexcept>

#include "../cpp/ipc_protocol.h"
#include "utils.h"

namespace flutter_wireguard {

namespace ipc_ns = ::flutter_wireguard::ipc;

namespace {

constexpr DWORD kConnectAttempts = 50;     // ~10 seconds total
constexpr DWORD kConnectSleepMs = 200;
constexpr DWORD kRequestTimeoutMs = 30'000;

bool ReadFully(HANDLE h, void* buf, DWORD len) {
  BYTE* p = static_cast<BYTE*>(buf);
  while (len > 0) {
    DWORD got = 0;
    if (!::ReadFile(h, p, len, &got, nullptr) || got == 0) return false;
    p += got;
    len -= got;
  }
  return true;
}

bool WriteFully(HANDLE h, const void* buf, DWORD len) {
  const BYTE* p = static_cast<const BYTE*>(buf);
  while (len > 0) {
    DWORD wrote = 0;
    if (!::WriteFile(h, p, len, &wrote, nullptr) || wrote == 0) return false;
    p += wrote;
    len -= wrote;
  }
  return true;
}

std::wstring HelperPathFromModule() {
  HMODULE mod = nullptr;
  if (!::GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCWSTR>(&HelperPathFromModule), &mod)) {
    return {};
  }
  wchar_t buf[MAX_PATH];
  DWORD n = ::GetModuleFileNameW(mod, buf, MAX_PATH);
  if (n == 0 || n == MAX_PATH) return {};
  std::wstring p(buf, n);
  size_t slash = p.find_last_of(L"\\/");
  if (slash == std::wstring::npos) return {};
  return p.substr(0, slash) + L"\\flutter_wireguard_helper.exe";
}

}  // namespace

BrokerClient& BrokerClient::Instance() {
  static BrokerClient inst;
  return inst;
}

BrokerClient::~BrokerClient() { Shutdown(); }

void BrokerClient::Shutdown() {
  stop_.store(true);
  HANDLE h = INVALID_HANDLE_VALUE;
  {
    std::lock_guard<std::mutex> lock(mu_);
    h = pipe_;
    pipe_ = INVALID_HANDLE_VALUE;
  }
  if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
  if (reader_.joinable()) reader_.join();
}

void BrokerClient::SetStatusCallback(StatusCallback cb) {
  std::lock_guard<std::mutex> lock(mu_);
  status_cb_ = std::move(cb);
}

std::wstring BrokerClient::ResolveHelperPath() {
  if (!helper_path_.empty()) return helper_path_;
  helper_path_ = HelperPathFromModule();
  return helper_path_;
}

HANDLE BrokerClient::LaunchBrokerAndConnect() {
  DWORD session_id = ::WTSGetActiveConsoleSessionId();
  if (session_id == 0xFFFFFFFFu) {
    throw std::runtime_error("could not resolve console session id");
  }

  std::wstring helper = ResolveHelperPath();
  if (helper.empty()) {
    throw std::runtime_error("could not resolve helper exe path");
  }

  // Build pipe name for this session.
  wchar_t pipe_buf[128];
  ::swprintf_s(pipe_buf, sizeof(pipe_buf) / sizeof(pipe_buf[0]),
               ipc_ns::kPipeNameFormat, static_cast<unsigned long>(session_id));
  std::wstring pipe_name = pipe_buf;

  // First, try connecting (broker may already be running from a prior
  // launch in the same session).
  for (DWORD i = 0; i < 5; ++i) {
    HANDLE h = ::CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) return h;
    if (::GetLastError() != ERROR_FILE_NOT_FOUND) break;
    ::Sleep(50);
  }

  // Not running. Launch elevated.
  std::wstring args = L"--broker --session-id " + std::to_wstring(session_id);
  SHELLEXECUTEINFOW info{};
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  info.lpVerb = L"runas";  // triggers UAC
  info.lpFile = helper.c_str();
  info.lpParameters = args.c_str();
  info.nShow = SW_HIDE;
  if (!::ShellExecuteExW(&info)) {
    throw std::runtime_error(
        ErrorWithCode("ShellExecuteEx(runas helper)", ::GetLastError()));
  }
  if (info.hProcess != nullptr) ::CloseHandle(info.hProcess);

  // Now poll for the pipe to appear.
  for (DWORD i = 0; i < kConnectAttempts; ++i) {
    HANDLE h = ::CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE,
                             0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) return h;
    DWORD err = ::GetLastError();
    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) {
      throw std::runtime_error(ErrorWithCode("CreateFile(pipe)", err));
    }
    ::Sleep(kConnectSleepMs);
  }
  throw std::runtime_error("timed out waiting for broker pipe");
}

void BrokerClient::EnsureConnected() {
  if (pipe_ != INVALID_HANDLE_VALUE) return;
  HANDLE h = LaunchBrokerAndConnect();
  pipe_ = h;
  stop_.store(false);
  reader_ = std::thread(&BrokerClient::ReaderLoop, this);

  // HELLO handshake.
  ipc_ns::Writer w;
  w.U32(ipc_ns::kProtocolVersion);
  auto resp = Request(ipc_ns::kOpHello, w.Take());
  ipc_ns::Reader r(resp.data(), resp.size());
  if (r.U8() != ipc_ns::kStatusOk) {
    throw std::runtime_error("broker refused hello: " + r.Str());
  }
  uint32_t broker_v = r.U32();
  if (broker_v != ipc_ns::kProtocolVersion) {
    throw std::runtime_error("broker protocol version mismatch");
  }

  // Subscribe to status events.
  Request(ipc_ns::kOpSubscribe, {});
}

void BrokerClient::ReaderLoop() {
  HANDLE h = pipe_;
  while (!stop_.load()) {
    uint32_t total = 0;
    if (!ReadFully(h, &total, sizeof(total))) break;
    if (total < 9 || total > ipc_ns::kMaxFrameBytes) break;
    std::vector<uint8_t> body(total);
    if (!ReadFully(h, body.data(), total)) break;
    ipc_ns::Reader r(body.data(), body.size());
    uint32_t op = r.U32();
    uint32_t seq = r.U32();
    uint8_t flags = r.U8();
    std::vector<uint8_t> payload(body.begin() + 9, body.end());
    (void)op;

    if ((flags & ipc_ns::kFlagEvent) != 0) {
      // Status event. Decode and dispatch.
      try {
        ipc_ns::Reader pr(payload.data(), payload.size());
        if (pr.U8() != ipc_ns::kStatusOk) continue;
        BrokerStatus s;
        s.name = pr.Str();
        s.state = pr.U8();
        s.rx = pr.I64();
        s.tx = pr.I64();
        s.handshake_ms = pr.I64();
        StatusCallback cb;
        {
          std::lock_guard<std::mutex> lock(mu_);
          cb = status_cb_;
        }
        if (cb) cb(s);
      } catch (...) {
      }
      continue;
    }

    std::shared_ptr<Pending> pending;
    {
      std::lock_guard<std::mutex> lock(mu_);
      auto it = inflight_.find(seq);
      if (it == inflight_.end()) continue;
      pending = it->second;
      inflight_.erase(it);
    }
    pending->payload = std::move(payload);
    pending->ready = true;
    cv_.notify_all();
  }

  // Pipe closed. Fail every outstanding request.
  std::lock_guard<std::mutex> lock(mu_);
  for (auto& kv : inflight_) {
    kv.second->error = "broker disconnected";
    kv.second->ready = true;
  }
  inflight_.clear();
  if (pipe_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
  }
  cv_.notify_all();
}

std::vector<uint8_t> BrokerClient::Request(uint32_t op,
                                           const std::vector<uint8_t>& payload) {
  uint32_t seq = 0;
  std::shared_ptr<Pending> pending = std::make_shared<Pending>();
  {
    std::lock_guard<std::mutex> lock(mu_);
    seq = next_seq_++;
    if (seq == 0) seq = next_seq_++;  // 0 reserved for events
    inflight_[seq] = pending;
  }
  std::vector<uint8_t> frame =
      ipc_ns::BuildFrame(op, seq, ipc_ns::kFlagNone, payload);
  if (!WriteFully(pipe_, frame.data(), static_cast<DWORD>(frame.size()))) {
    std::lock_guard<std::mutex> lock(mu_);
    inflight_.erase(seq);
    throw std::runtime_error("failed to write to broker pipe");
  }

  std::unique_lock<std::mutex> lock(mu_);
  if (!cv_.wait_for(lock, std::chrono::milliseconds(kRequestTimeoutMs),
                    [&] { return pending->ready; })) {
    inflight_.erase(seq);
    throw std::runtime_error("broker request timed out");
  }
  if (!pending->error.empty()) {
    throw std::runtime_error(pending->error);
  }
  return pending->payload;
}

namespace {

void CheckOk(ipc_ns::Reader& r) {
  if (r.U8() != ipc_ns::kStatusOk) {
    throw std::runtime_error(r.Str());
  }
}

}  // namespace

void BrokerClient::Start(const std::string& name, const std::string& config) {
  EnsureConnected();
  ipc_ns::Writer w;
  w.Str(name);
  w.Str(config);
  auto resp = Request(ipc_ns::kOpStart, w.Take());
  ipc_ns::Reader r(resp.data(), resp.size());
  CheckOk(r);
}

void BrokerClient::Stop(const std::string& name) {
  EnsureConnected();
  ipc_ns::Writer w;
  w.Str(name);
  auto resp = Request(ipc_ns::kOpStop, w.Take());
  ipc_ns::Reader r(resp.data(), resp.size());
  CheckOk(r);
}

BrokerStatus BrokerClient::Status(const std::string& name) {
  EnsureConnected();
  ipc_ns::Writer w;
  w.Str(name);
  auto resp = Request(ipc_ns::kOpStatus, w.Take());
  ipc_ns::Reader r(resp.data(), resp.size());
  CheckOk(r);
  BrokerStatus s;
  s.name = r.Str();
  s.state = r.U8();
  s.rx = r.I64();
  s.tx = r.I64();
  s.handshake_ms = r.I64();
  return s;
}

std::vector<std::string> BrokerClient::TunnelNames() {
  EnsureConnected();
  auto resp = Request(ipc_ns::kOpTunnelNames, {});
  ipc_ns::Reader r(resp.data(), resp.size());
  CheckOk(r);
  uint32_t n = r.U32();
  std::vector<std::string> out;
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) out.push_back(r.Str());
  return out;
}

BrokerBackend BrokerClient::Backend() {
  EnsureConnected();
  auto resp = Request(ipc_ns::kOpBackend, {});
  ipc_ns::Reader r(resp.data(), resp.size());
  CheckOk(r);
  BrokerBackend b;
  b.kind = r.U8();
  b.detail = r.Str();
  return b;
}

}  // namespace flutter_wireguard
