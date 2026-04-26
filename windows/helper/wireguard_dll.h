#ifndef FLUTTER_WIREGUARD_HELPER_WIREGUARD_DLL_H_
#define FLUTTER_WIREGUARD_HELPER_WIREGUARD_DLL_H_

#include <windows.h>

#include <string>

namespace flutter_wireguard {

struct WireGuardStats {
  int64_t rx = 0;
  int64_t tx = 0;
  int64_t handshake_ms = 0;  // Unix epoch ms; 0 if no handshake yet.
};

// Lazy-loaded wrapper around wireguard.dll's WireGuardOpenAdapter /
// WireGuardGetConfiguration / WireGuardCloseAdapter. Calling QueryStats from
// an unprivileged process always fails; the broker (which is elevated) is the
// intended caller.
class WireGuardDll {
 public:
  static WireGuardDll& Instance();

  // Returns true and fills *out on success. Returns false (with no log) when
  // the adapter is simply not present (DOWN tunnel) or the DLL isn't
  // available; details go via OutputDebugString for crash dumps.
  bool QueryStats(const std::wstring& adapter_name, WireGuardStats* out);

 private:
  WireGuardDll() = default;
  bool Load();

  HMODULE module_ = nullptr;
  using OpenAdapterFn = void*(WINAPI*)(const wchar_t*);
  using CloseAdapterFn = void(WINAPI*)(void*);
  using GetConfigurationFn = BOOL(WINAPI*)(void*, void*, DWORD*);
  OpenAdapterFn open_ = nullptr;
  CloseAdapterFn close_ = nullptr;
  GetConfigurationFn get_config_ = nullptr;
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_HELPER_WIREGUARD_DLL_H_
