#include "wireguard_dll.h"

#include <vector>

#include "../utils.h"
#include "wireguard.h"

namespace flutter_wireguard {

namespace {

constexpr unsigned long long kFileTimeToUnixEpoch100ns = 116444736000000000ULL;

int64_t FileTime100nsToUnixMs(unsigned long long ticks) {
  if (ticks == 0 || ticks < kFileTimeToUnixEpoch100ns) return 0;
  return static_cast<int64_t>((ticks - kFileTimeToUnixEpoch100ns) / 10000ULL);
}

}  // namespace

WireGuardDll& WireGuardDll::Instance() {
  static WireGuardDll instance;
  return instance;
}

bool WireGuardDll::Load() {
  if (module_ != nullptr) return open_ && close_ && get_config_;
  module_ = ::LoadLibraryW(L"wireguard.dll");
  if (module_ == nullptr) {
    Log(ErrorWithCode("LoadLibrary(wireguard.dll)", ::GetLastError()));
    return false;
  }
  open_ = reinterpret_cast<OpenAdapterFn>(
      ::GetProcAddress(module_, "WireGuardOpenAdapter"));
  close_ = reinterpret_cast<CloseAdapterFn>(
      ::GetProcAddress(module_, "WireGuardCloseAdapter"));
  get_config_ = reinterpret_cast<GetConfigurationFn>(
      ::GetProcAddress(module_, "WireGuardGetConfiguration"));
  return open_ && close_ && get_config_;
}

bool WireGuardDll::QueryStats(const std::wstring& adapter_name,
                              WireGuardStats* out) {
  if (out == nullptr) return false;
  *out = {};
  if (!Load()) return false;

  void* adapter = open_(adapter_name.c_str());
  if (adapter == nullptr) return false;

  DWORD bytes = sizeof(WIREGUARD_INTERFACE) + 64 * 1024;
  std::vector<BYTE> buf(bytes);
  BOOL ok = get_config_(adapter, buf.data(), &bytes);
  if (!ok && ::GetLastError() == ERROR_MORE_DATA) {
    buf.resize(bytes);
    ok = get_config_(adapter, buf.data(), &bytes);
  }
  if (!ok) {
    close_(adapter);
    return false;
  }

  auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
  BYTE* cursor = buf.data() + sizeof(WIREGUARD_INTERFACE);
  unsigned long long max_handshake = 0;
  unsigned long long sum_rx = 0, sum_tx = 0;
  for (DWORD i = 0; i < iface->PeersCount; ++i) {
    auto* peer = reinterpret_cast<WIREGUARD_PEER*>(cursor);
    sum_rx += peer->RxBytes;
    sum_tx += peer->TxBytes;
    if (peer->LastHandshake > max_handshake) max_handshake = peer->LastHandshake;
    cursor += sizeof(WIREGUARD_PEER) +
              static_cast<size_t>(peer->AllowedIPsCount) *
                  sizeof(WIREGUARD_ALLOWED_IP);
  }
  out->rx = static_cast<int64_t>(sum_rx);
  out->tx = static_cast<int64_t>(sum_tx);
  out->handshake_ms = FileTime100nsToUnixMs(max_handshake);
  close_(adapter);
  return true;
}

}  // namespace flutter_wireguard
