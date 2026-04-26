// Entry point for flutter_wireguard_helper.exe.
//
// Two modes, dispatched off argv[1]:
//
//   --broker --session-id <id>
//       Runs the elevated named-pipe broker for the user owning session <id>.
//       Started by the plugin via ShellExecuteEx("runas") on first plugin call.
//
//   --tunnel-service <conf-path>
//       Started by the Service Control Manager. Loads tunnel.dll and runs
//       the WireGuard packet-tunnel goroutine until SCM stops it.
//
// Anything else => print usage and exit 64 (EX_USAGE).

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>

#include "broker.h"
#include "tunnel_service.h"
#include "../utils.h"

using flutter_wireguard::Broker;
using flutter_wireguard::Log;
using flutter_wireguard::RunTunnelService;

namespace {

int Usage() {
  std::fwprintf(
      stderr,
      L"flutter_wireguard_helper.exe\n"
      L"  --broker --session-id <id>     run the elevated IPC broker\n"
      L"  --tunnel-service <conf-path>   SCM entry, runs tunnel.dll\n");
  return 64;
}

std::wstring SelfPath() {
  wchar_t buf[MAX_PATH];
  DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
  if (n == 0 || n == MAX_PATH) return {};
  return std::wstring(buf, n);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc < 2) return Usage();
  std::wstring mode = argv[1];

  if (mode == L"--broker") {
    DWORD session_id = 0xFFFFFFFFu;
    for (int i = 2; i + 1 < argc; ++i) {
      if (std::wcscmp(argv[i], L"--session-id") == 0) {
        session_id = static_cast<DWORD>(std::wcstoul(argv[i + 1], nullptr, 10));
      }
    }
    if (session_id == 0xFFFFFFFFu) return Usage();
    Broker broker(SelfPath(), session_id);
    return broker.Run();
  }

  if (mode == L"--tunnel-service") {
    if (argc < 3) return Usage();
    return RunTunnelService(argv[2]);
  }

  return Usage();
}
