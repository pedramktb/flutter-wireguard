#include "tunnel_service.h"

#include <windows.h>

#include <string>
#include <vector>

#include "../utils.h"

namespace flutter_wireguard {

namespace {

// Embeddable WireGuardTunnelService (from the Go embeddable-dll-service
// package). When invoked it performs the full Windows-service lifecycle
// itself \u2014 including StartServiceCtrlDispatcher \u2014 so callers must NOT
// register a separate SCM dispatcher of their own.
//
// The exported symbol returns a Go bool, marshalled as a 1-byte cdecl value:
//   nonzero = service ran to completion successfully
//   zero    = startup failed (see %WINDIR%\Temp\flutter_wireguard.log)
using WireGuardTunnelServiceFn = unsigned char(__cdecl*)(unsigned short*);

std::wstring HelperDir() {
  wchar_t buf[MAX_PATH];
  DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
  if (n == 0 || n == MAX_PATH) return {};
  std::wstring p(buf, n);
  size_t slash = p.find_last_of(L"\\/");
  if (slash == std::wstring::npos) return {};
  return p.substr(0, slash);
}

}  // namespace

int RunTunnelService(const std::wstring& conf_path) {
  Log(std::wstring(L"tunnel-service: RunTunnelService conf=") + conf_path);

  // Services start with cwd = C:\Windows\System32. Make sure tunnel.dll
  // and its sibling wireguard.dll resolve from where helper.exe lives.
  std::wstring dir = HelperDir();
  if (!dir.empty()) {
    ::SetCurrentDirectoryW(dir.c_str());
    ::SetDllDirectoryW(dir.c_str());
  }

  std::wstring tunnel_path =
      dir.empty() ? L"tunnel.dll" : (dir + L"\\tunnel.dll");
  HMODULE mod = ::LoadLibraryExW(
      tunnel_path.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
  if (mod == nullptr) {
    Log(ErrorWithCode("LoadLibrary(tunnel.dll)", ::GetLastError()));
    return 5;
  }
  auto fn = reinterpret_cast<WireGuardTunnelServiceFn>(
      ::GetProcAddress(mod, "WireGuardTunnelService"));
  if (fn == nullptr) {
    Log(ErrorWithCode("GetProcAddress(WireGuardTunnelService)",
                      ::GetLastError()));
    return 6;
  }

  // WireGuardTunnelService internally calls StartServiceCtrlDispatcher and
  // blocks until SCM stops the service. Do NOT wrap it in our own dispatcher
  // \u2014 that would trigger ERROR_SERVICE_ALREADY_RUNNING on the inner call
  // and the function returns false (=0) immediately.
  std::vector<wchar_t> buf(conf_path.begin(), conf_path.end());
  buf.push_back(L'\0');
  unsigned char rc = fn(reinterpret_cast<unsigned short*>(buf.data()));
  Log(std::string("tunnel-service: WireGuardTunnelService returned ") +
      std::to_string(static_cast<int>(rc)));
  return rc != 0 ? 0 : 7;
}

}  // namespace flutter_wireguard
