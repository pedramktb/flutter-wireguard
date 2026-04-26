#include "tunnel_service.h"

#include <windows.h>

#include <vector>

#include "../utils.h"

namespace flutter_wireguard {

namespace {

// We deliberately LoadLibrary tunnel.dll instead of linking against tunnel.lib
// (no .lib is shipped with the embeddable Go DLL; cgo only emits the .h) and
// to keep helper.exe runnable for unit tests on machines without the DLL.
using WireGuardTunnelServiceFn = unsigned char(__cdecl*)(unsigned short*);

std::wstring g_conf_path;

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
  HMODULE mod = ::LoadLibraryW(L"tunnel.dll");
  if (mod == nullptr) {
    Log(ErrorWithCode("LoadLibrary(tunnel.dll)", ::GetLastError()));
    return;
  }
  auto fn = reinterpret_cast<WireGuardTunnelServiceFn>(
      ::GetProcAddress(mod, "WireGuardTunnelService"));
  if (fn == nullptr) {
    Log(ErrorWithCode("GetProcAddress(WireGuardTunnelService)",
                      ::GetLastError()));
    return;
  }
  std::vector<wchar_t> buf(g_conf_path.begin(), g_conf_path.end());
  buf.push_back(L'\0');
  (void)fn(reinterpret_cast<unsigned short*>(buf.data()));
}

}  // namespace

int RunTunnelService(const std::wstring& conf_path) {
  g_conf_path = conf_path;

  // The empty service-name buffer combined with SERVICE_WIN32_OWN_PROCESS
  // tells SCM to use whatever name was passed to CreateService — that's our
  // WireGuardTunnel$<name>.
  wchar_t name_buf[1] = {L'\0'};
  SERVICE_TABLE_ENTRYW table[] = {
      {name_buf, ServiceMain},
      {nullptr, nullptr},
  };

  if (!::StartServiceCtrlDispatcherW(table)) {
    Log(ErrorWithCode("StartServiceCtrlDispatcher", ::GetLastError()));
    return 5;
  }
  return 0;
}

}  // namespace flutter_wireguard
