#ifndef FLUTTER_WIREGUARD_HELPER_TUNNEL_MANAGER_H_
#define FLUTTER_WIREGUARD_HELPER_TUNNEL_MANAGER_H_

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace flutter_wireguard {

struct TunnelStatusSnapshot {
  std::string name;
  // 0=down, 1=toggle, 2=up — same numeric values as TunnelStateWire.
  uint8_t state = 0;
  int64_t rx = 0;
  int64_t tx = 0;
  int64_t handshake_ms = 0;
};

struct BackendInfoSnapshot {
  // 0=kernel, 1=userspace, 2=unknown.
  uint8_t kind = 1;
  std::string detail;
};

// All tunnel orchestration runs in the broker process (which is admin).
//
// Service naming:  WireGuardTunnel$<name>  (the dollar-suffix form is the
// convention used by wireguard-windows itself; ListServices filters on it).
//
// Exec line: "<helper.exe>" --tunnel-service "<dpapi-config-path>"
//   The helper, when running under the SCM, locates the matching tunnel name
//   via the file basename and calls WireGuardTunnelService(<plaintext .conf>).
class TunnelManager {
 public:
  // helper_path = absolute path to flutter_wireguard_helper.exe (UTF-16).
  explicit TunnelManager(std::wstring helper_path);
  ~TunnelManager();

  TunnelManager(const TunnelManager&) = delete;
  TunnelManager& operator=(const TunnelManager&) = delete;

  // Throws std::runtime_error on failure. Must be called with a name that has
  // already been validated by IsValidTunnelName.
  void Start(const std::string& name, const std::string& config);
  void Stop(const std::string& name);
  TunnelStatusSnapshot Status(const std::string& name);
  std::vector<std::string> TunnelNames() const;
  BackendInfoSnapshot Backend() const;

  // Sets a callback invoked from a background thread whenever a known tunnel
  // changes state or every ~1 s while UP (rx/tx/handshake refresh).
  using StatusCallback = std::function<void(const TunnelStatusSnapshot&)>;
  void SetStatusCallback(StatusCallback cb);

  // Stops the background poller. Idempotent.
  void Shutdown();

 private:
  void EnsurePollerStarted();
  void PollLoop();
  TunnelStatusSnapshot QueryStatusUnlocked(const std::string& name);

  std::wstring helper_path_;
  mutable std::mutex mu_;
  std::set<std::string> known_tunnels_;            // touched this session
  std::set<std::string> last_emitted_state_;       // for diffing
  StatusCallback callback_;
  std::thread poller_;
  std::atomic<bool> stop_{false};
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_HELPER_TUNNEL_MANAGER_H_
