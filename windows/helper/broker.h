#ifndef FLUTTER_WIREGUARD_HELPER_BROKER_H_
#define FLUTTER_WIREGUARD_HELPER_BROKER_H_

#include <windows.h>

#include <atomic>
#include <memory>
#include <string>

#include "tunnel_manager.h"

namespace flutter_wireguard {

// Listens on a named pipe (per-user-DACL'd) and dispatches IPC frames to a
// TunnelManager. Single-client; the plugin reconnects if the pipe closes.
class Broker {
 public:
  Broker(std::wstring helper_path, DWORD client_session_id);
  ~Broker();

  Broker(const Broker&) = delete;
  Broker& operator=(const Broker&) = delete;

  // Blocks. Returns 0 on clean shutdown, non-zero on fatal init failure.
  int Run();

 private:
  void HandleClient(HANDLE pipe);
  void EmitStatus(HANDLE pipe, const TunnelStatusSnapshot& s);

  std::wstring helper_path_;
  DWORD client_session_id_;
  std::unique_ptr<TunnelManager> manager_;
};

// Computes the broker pipe name for `session_id`.
std::wstring BrokerPipeName(DWORD session_id);

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_HELPER_BROKER_H_
