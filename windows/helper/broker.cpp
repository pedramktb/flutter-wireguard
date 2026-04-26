#include "broker.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#include "../../cpp/ipc_protocol.h"
#include "../../cpp/name_validator.h"
#include "../utils.h"
#include "pipe_security.h"

namespace flutter_wireguard {

namespace ipc_ns = ::flutter_wireguard::ipc;

namespace {

constexpr DWORD kPipeBuf = 64 * 1024;
constexpr DWORD kIdleTimeoutMs = 60'000;

bool ReadFully(HANDLE pipe, void* buf, DWORD len) {
  BYTE* p = static_cast<BYTE*>(buf);
  while (len > 0) {
    DWORD got = 0;
    OVERLAPPED ov{};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr) return false;
    BOOL ok = ::ReadFile(pipe, p, len, &got, &ov);
    if (!ok && ::GetLastError() == ERROR_IO_PENDING) {
      ok = ::GetOverlappedResult(pipe, &ov, &got, TRUE);
    }
    ::CloseHandle(ov.hEvent);
    if (!ok || got == 0) {
      Log(ErrorWithCode("broker ReadFile", ::GetLastError()));
      return false;
    }
    p += got;
    len -= got;
  }
  return true;
}

bool WriteFully(HANDLE pipe, const void* buf, DWORD len) {
  const BYTE* p = static_cast<const BYTE*>(buf);
  while (len > 0) {
    DWORD wrote = 0;
    OVERLAPPED ov{};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr) return false;
    BOOL ok = ::WriteFile(pipe, p, len, &wrote, &ov);
    if (!ok && ::GetLastError() == ERROR_IO_PENDING) {
      ok = ::GetOverlappedResult(pipe, &ov, &wrote, TRUE);
    }
    ::CloseHandle(ov.hEvent);
    if (!ok || wrote == 0) return false;
    p += wrote;
    len -= wrote;
  }
  return true;
}

bool ReadFrame(HANDLE pipe, uint32_t* op, uint32_t* seq, uint8_t* flags,
               std::vector<uint8_t>* payload) {
  uint32_t total = 0;
  if (!ReadFully(pipe, &total, sizeof(total))) return false;
  if (total < 9 || total > ipc_ns::kMaxFrameBytes) return false;
  std::vector<uint8_t> body(total);
  if (!ReadFully(pipe, body.data(), total)) return false;
  ipc_ns::Reader r(body.data(), body.size());
  *op = r.U32();
  *seq = r.U32();
  *flags = r.U8();
  payload->assign(body.begin() + 9, body.end());
  return true;
}

bool WriteResponse(HANDLE pipe, uint32_t seq,
                   const std::vector<uint8_t>& payload, uint8_t flags = 0) {
  std::vector<uint8_t> frame =
      ipc_ns::BuildFrame(0 /* op unused on resp */, seq, flags, payload);
  // Op field on resp is ignored by the client; use 0 to be explicit.
  return WriteFully(pipe, frame.data(), static_cast<DWORD>(frame.size()));
}

std::vector<uint8_t> Ok() {
  ipc_ns::Writer w;
  w.U8(ipc_ns::kStatusOk);
  return w.Take();
}

std::vector<uint8_t> Err(const std::string& msg) {
  ipc_ns::Writer w;
  w.U8(ipc_ns::kStatusError);
  w.Str(msg);
  return w.Take();
}

std::vector<uint8_t> EncodeStatus(const TunnelStatusSnapshot& s) {
  ipc_ns::Writer w;
  w.U8(ipc_ns::kStatusOk);
  w.Str(s.name);
  w.U8(s.state);
  w.I64(s.rx);
  w.I64(s.tx);
  w.I64(s.handshake_ms);
  return w.Take();
}

}  // namespace

std::wstring BrokerPipeName(DWORD session_id) {
  wchar_t buf[128];
  ::swprintf_s(buf, sizeof(buf) / sizeof(buf[0]), ipc_ns::kPipeNameFormat,
               static_cast<unsigned long>(session_id));
  return std::wstring(buf);
}

Broker::Broker(std::wstring helper_path, DWORD client_session_id)
    : helper_path_(std::move(helper_path)),
      client_session_id_(client_session_id) {
  manager_ = std::make_unique<TunnelManager>(helper_path_);
}

Broker::~Broker() = default;

void Broker::EmitStatus(HANDLE pipe, const TunnelStatusSnapshot& s) {
  auto payload = EncodeStatus(s);
  std::vector<uint8_t> frame = ipc_ns::BuildFrame(
      ipc_ns::kOpEventStatus, 0 /* seq=0 -> event */, ipc_ns::kFlagEvent,
      payload);
  // Best-effort: ignore failures (client disconnected; HandleClient's read
  // loop will see it next).
  WriteFully(pipe, frame.data(), static_cast<DWORD>(frame.size()));
}

void Broker::HandleClient(HANDLE pipe) {
  // Status events are emitted from the TunnelManager's poller thread; they
  // race with our own response writes, so serialize all writes to this pipe.
  std::mutex pipe_write_mu;
  manager_->SetStatusCallback(
      [this, pipe, &pipe_write_mu](const TunnelStatusSnapshot& s) {
        std::lock_guard<std::mutex> lock(pipe_write_mu);
        EmitStatus(pipe, s);
      });

  for (;;) {
    uint32_t op = 0, seq = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
    if (!ReadFrame(pipe, &op, &seq, &flags, &payload)) {
      break;
    }

    std::vector<uint8_t> resp;
    try {
      ipc_ns::Reader r(payload.data(), payload.size());
      switch (op) {
        case ipc_ns::kOpHello: {
          uint32_t client_v = r.U32();
          if (client_v != ipc_ns::kProtocolVersion) {
            resp = Err("protocol version mismatch");
            break;
          }
          ipc_ns::Writer w;
          w.U8(ipc_ns::kStatusOk);
          w.U32(ipc_ns::kProtocolVersion);
          resp = w.Take();
          break;
        }
        case ipc_ns::kOpStart: {
          std::string name = r.Str();
          std::string config = r.Str();
          if (!IsValidTunnelName(name)) {
            resp = Err("invalid tunnel name");
            break;
          }
          if (config.size() > ipc_ns::kMaxConfigBytes) {
            resp = Err("config too large");
            break;
          }
          manager_->Start(name, config);
          resp = Ok();
          break;
        }
        case ipc_ns::kOpStop: {
          std::string name = r.Str();
          if (!IsValidTunnelName(name)) {
            resp = Err("invalid tunnel name");
            break;
          }
          manager_->Stop(name);
          resp = Ok();
          break;
        }
        case ipc_ns::kOpStatus: {
          std::string name = r.Str();
          if (!IsValidTunnelName(name)) {
            resp = Err("invalid tunnel name");
            break;
          }
          TunnelStatusSnapshot s = manager_->Status(name);
          resp = EncodeStatus(s);
          break;
        }
        case ipc_ns::kOpTunnelNames: {
          ipc_ns::Writer w;
          w.U8(ipc_ns::kStatusOk);
          auto names = manager_->TunnelNames();
          w.U32(static_cast<uint32_t>(names.size()));
          for (const auto& n : names) w.Str(n);
          resp = w.Take();
          break;
        }
        case ipc_ns::kOpBackend: {
          ipc_ns::Writer w;
          w.U8(ipc_ns::kStatusOk);
          BackendInfoSnapshot b = manager_->Backend();
          w.U8(b.kind);
          w.Str(b.detail);
          resp = w.Take();
          break;
        }
        case ipc_ns::kOpSubscribe: {
          resp = Ok();
          break;
        }
        default:
          resp = Err("unknown op");
          break;
      }
    } catch (const std::exception& e) {
      resp = Err(e.what() ? e.what() : "");
    } catch (...) {
      resp = Err("unknown error");
    }

    std::lock_guard<std::mutex> lock(pipe_write_mu);
    if (!WriteResponse(pipe, seq, resp)) {
      break;
    }
  }

  manager_->SetStatusCallback({});
  ::FlushFileBuffers(pipe);
  ::DisconnectNamedPipe(pipe);
}

int Broker::Run() {
  std::wstring pipe_name = BrokerPipeName(client_session_id_);
  Log(std::wstring(L"Broker::Run pipe=") + pipe_name);

  // Build a SECURITY_ATTRIBUTES granting access to the launching user only.
  // Note: the broker runs as Administrator, but the *client* might be the
  // un-elevated user; we want pipe writes from that user (and only that user)
  // to succeed.
  PSID user_sid = GetActiveConsoleUserSid();
  if (user_sid == nullptr) {
    Log(L"failed to resolve interactive user SID");
    return 2;
  }
  std::unique_ptr<PipeSecurity> sec = PipeSecurity::Create(user_sid);
  ::LocalFree(user_sid);
  if (sec == nullptr) {
    Log(L"failed to build pipe security descriptor");
    return 3;
  }

  for (;;) {
    HANDLE pipe = ::CreateNamedPipeW(
        pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE |
            FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        1, kPipeBuf, kPipeBuf, kIdleTimeoutMs, sec->sa());
    if (pipe == INVALID_HANDLE_VALUE) {
      Log(ErrorWithCode("CreateNamedPipe", ::GetLastError()));
      return 4;
    }

    OVERLAPPED ov{};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL connected = ::ConnectNamedPipe(pipe, &ov);
    DWORD cerr = ::GetLastError();
    if (!connected && cerr == ERROR_IO_PENDING) {
      DWORD bytes = 0;
      connected = ::GetOverlappedResult(pipe, &ov, &bytes, TRUE);
      cerr = ::GetLastError();
    }
    ::CloseHandle(ov.hEvent);
    if (!connected && cerr != ERROR_PIPE_CONNECTED) {
      Log(ErrorWithCode("ConnectNamedPipe", cerr));
      ::CloseHandle(pipe);
      continue;
    }
    Log("Broker: client connected, entering HandleClient");
    HandleClient(pipe);
    ::CloseHandle(pipe);
    // Client disconnected. Exit so a future plugin instance starts a fresh
    // broker (with a single UAC prompt) instead of inheriting state from a
    // previous Flutter process. The pipe's idle timeout would eventually do
    // the same thing, but only after kIdleTimeoutMs and only if no other
    // client connects in the meantime.
    return 0;
  }
}

}  // namespace flutter_wireguard
