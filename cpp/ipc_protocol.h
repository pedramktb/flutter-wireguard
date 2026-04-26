// Wire protocol shared by the Flutter plugin (UI process) and the elevated
// flutter_wireguard_helper.exe broker.
//
// Transport: a Windows named pipe in BYTE/MESSAGE mode is fine; we use
// length-prefixed BYTE frames so the same code works either way.
//
// Frame (both directions):
//
//   [u32 LE total_len][u32 LE op][u32 LE seq][u8 flags][payload...]
//
// total_len counts every byte after itself, i.e. 4(op)+4(seq)+1(flags)+|payload|.
//
// Requests carry a non-zero seq; responses echo it. Asynchronous status
// events use seq=0 and have flags & kFlagEvent set.
//
// Strings are u32 LE length + UTF-8 bytes. Keeping things explicit avoids
// pulling JSON / Pigeon into the broker, which must stay tiny and
// Flutter-free.
#ifndef FLUTTER_WIREGUARD_IPC_PROTOCOL_H_
#define FLUTTER_WIREGUARD_IPC_PROTOCOL_H_

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace flutter_wireguard {
namespace ipc {

// Bump on every wire-incompatible change. The broker rejects any client whose
// HELLO reports a different value.
inline constexpr uint32_t kProtocolVersion = 1;

// Pipe-name pattern. The %lu is replaced with the launching session id so two
// users on the same machine never collide.
inline constexpr wchar_t kPipeNameFormat[] = L"\\\\.\\pipe\\flutter_wireguard_broker_%lu";

enum Op : uint32_t {
  kOpHello = 0,         // req: u32 client_version. resp: u32 broker_version.
  kOpStart = 1,         // req: str name, str config. resp: empty.
  kOpStop = 2,          // req: str name.             resp: empty.
  kOpStatus = 3,        // req: str name.             resp: TunnelStatusBlob.
  kOpTunnelNames = 4,   // req: empty.                resp: u32 count + [str]*.
  kOpBackend = 5,       // req: empty.                resp: u8 kind + str detail.
  kOpSubscribe = 6,     // req: empty. resp: empty; thereafter status events.
  kOpEventStatus = 128, // event: TunnelStatusBlob (seq=0, flags=kFlagEvent).
};

// Response status. First byte of every response payload.
enum Status : uint8_t {
  kStatusOk = 0,
  kStatusError = 1,    // followed by str message
};

// Frame flags bitset.
enum Flag : uint8_t {
  kFlagNone = 0,
  kFlagEvent = 1 << 0,
};

// Mirror of TunnelState in messages.g.h (kept independent so the broker
// doesn't need to link the Pigeon-generated header).
enum TunnelStateWire : uint8_t {
  kStateDown = 0,
  kStateToggle = 1,
  kStateUp = 2,
};

enum BackendKindWire : uint8_t {
  kBackendKernel = 0,
  kBackendUserspace = 1,
  kBackendUnknown = 2,
};

// Hard caps to keep the broker safe against a malicious peer in case the
// pipe ACL is ever loosened.
inline constexpr uint32_t kMaxNameBytes = 64;
inline constexpr uint32_t kMaxConfigBytes = 64 * 1024;
inline constexpr uint32_t kMaxFrameBytes = 128 * 1024;

// ---------- byte buffer helpers (header-only, no deps) ----------

class Writer {
 public:
  void U8(uint8_t v) { buf_.push_back(v); }
  void U32(uint32_t v) {
    for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
  }
  void I64(int64_t v) {
    auto u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<uint8_t>((u >> (i * 8)) & 0xff));
  }
  void Str(const std::string& s) {
    if (s.size() > kMaxConfigBytes) throw std::length_error("string too large");
    U32(static_cast<uint32_t>(s.size()));
    buf_.insert(buf_.end(), s.begin(), s.end());
  }
  std::vector<uint8_t> Take() { return std::move(buf_); }
  const std::vector<uint8_t>& Peek() const { return buf_; }

 private:
  std::vector<uint8_t> buf_;
};

class Reader {
 public:
  Reader(const uint8_t* data, size_t len) : p_(data), end_(data + len) {}

  uint8_t U8() {
    Need(1);
    return *p_++;
  }
  uint32_t U32() {
    Need(4);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p_[i]) << (i * 8);
    p_ += 4;
    return v;
  }
  int64_t I64() {
    Need(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p_[i]) << (i * 8);
    p_ += 8;
    return static_cast<int64_t>(v);
  }
  std::string Str() {
    uint32_t n = U32();
    if (n > kMaxConfigBytes) throw std::length_error("string too large");
    Need(n);
    std::string s(reinterpret_cast<const char*>(p_), n);
    p_ += n;
    return s;
  }
  bool Empty() const { return p_ == end_; }

 private:
  void Need(size_t n) {
    if (static_cast<size_t>(end_ - p_) < n) throw std::runtime_error("short read");
  }
  const uint8_t* p_;
  const uint8_t* end_;
};

// Builds a complete frame ready to write to the pipe.
inline std::vector<uint8_t> BuildFrame(uint32_t op, uint32_t seq, uint8_t flags,
                                       const std::vector<uint8_t>& payload) {
  if (payload.size() + 9 > kMaxFrameBytes) throw std::length_error("frame too large");
  std::vector<uint8_t> out;
  out.reserve(4 + 9 + payload.size());
  uint32_t total = 9 + static_cast<uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((total >> (i * 8)) & 0xff));
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((op >> (i * 8)) & 0xff));
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((seq >> (i * 8)) & 0xff));
  out.push_back(flags);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

}  // namespace ipc
}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_IPC_PROTOCOL_H_
