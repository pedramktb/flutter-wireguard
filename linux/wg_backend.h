// Linux WireGuard backend.
//
// Wraps wg-quick / wg with safe argv-based execution. Mirrors the Android
// strategy: prefer the kernel module (via wg-quick), fall back to a userspace
// implementation (wireguard-go / boringtun) by setting
// WG_QUICK_USERSPACE_IMPLEMENTATION when no kernel module is loaded.
//
// Privilege model:
//   - If the current process runs as root we invoke wg-quick directly.
//   - Otherwise Start/Stop are prefixed with `pkexec` and the polkit agent
//     will prompt the user (one prompt per Start/Stop).
//   - Status reads (`wg show ... dump`) are NEVER elevated. They are polled
//     once per second and elevating them would mean a pkexec prompt per tick.
//     If the unprivileged read fails the tunnel is reported as UP with zero
//     stats; full stats become available when the app runs as root or a
//     polkit rule grants CAP_NET_ADMIN to wg(8).
#ifndef FLUTTER_WIREGUARD_WG_BACKEND_H_
#define FLUTTER_WIREGUARD_WG_BACKEND_H_

#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "privileged_session.h"
#include "process_runner.h"

namespace flutter_wireguard {

enum class BackendKindCpp { kKernel, kUserspace, kUnknown };
enum class TunnelStateCpp { kDown, kToggle, kUp };

struct TunnelStatusCpp {
  std::string name;
  TunnelStateCpp state = TunnelStateCpp::kDown;
  int64_t rx = 0;
  int64_t tx = 0;
  int64_t handshake = 0;
};

struct BackendInfoCpp {
  BackendKindCpp kind = BackendKindCpp::kUnknown;
  std::string detail;
};

class WgBackend {
 public:
  // `runner` runs unprivileged probes (HasBinary, kernel module detect).
  // `elevated` runs privileged ops (wg-quick up/down, wg show). If null a
  // RealPrivilegedSession is constructed automatically using `runner`.
  explicit WgBackend(std::unique_ptr<ProcessRunner> runner,
                     std::string config_dir = std::string(),
                     std::unique_ptr<PrivilegedSession> elevated = nullptr);

  // Brings the named tunnel up. Throws std::runtime_error on failure.
  void Start(const std::string& name, const std::string& config);

  // Brings the named tunnel down. No-op if unknown / already down.
  void Stop(const std::string& name);

  // Snapshot of the named tunnel. Throws if `name` was never started.
  TunnelStatusCpp Status(const std::string& name);

  // Names of every tunnel touched in this process lifetime (UP or DOWN).
  std::vector<std::string> TunnelNames() const;

  // Active backend metadata.
  BackendInfoCpp Backend() const { return backend_; }

  // ----- Statics exposed for unit testing -----

  // Validates a Linux interface name against WireGuard's accepted character
  // set. Mirrors the kernel's check (max 15 bytes, [A-Za-z0-9_=+.-], cannot be
  // empty or "."/".." or contain '/').
  static bool IsValidName(const std::string& name);

  // Parses `wg show <name> dump` output into a TunnelStatusCpp aggregating rx,
  // tx and the latest handshake across all peers. Returns kUp if any peers are
  // listed (i.e. the dump succeeded), kDown otherwise.
  static TunnelStatusCpp ParseWgShowDump(const std::string& name,
                                         const std::string& dump_stdout);

  // Reads byte counters from /sys/class/net/<name>/statistics/{rx,tx}_bytes.
  // Both kernel WireGuard and the TUN device created by wireguard-go expose
  // these counters world-readable, so they work with no privilege escalation.
  // sysfs_root defaults to "/sys/class/net"; tests override it.
  // Returns false if the interface directory does not exist.
  static bool ReadSysfsCounters(const std::string& name,
                                int64_t* rx,
                                int64_t* tx,
                                const std::string& sysfs_root = "/sys/class/net");

 private:
  // Writes config to a private file inside config_dir_. Returns absolute path.
  std::string WriteConfigFile(const std::string& name, const std::string& config);

  // Detects the active backend at construction.
  void DetectBackend();

  // Returns the userspace impl name for env var, or "" if kernel mode.
  std::string PickUserspaceImpl() const;

  std::unique_ptr<ProcessRunner>     runner_;
  std::unique_ptr<PrivilegedSession> elevated_;
  std::string config_dir_;
  std::string sysfs_root_ = "/sys/class/net";  // overridable for tests
  BackendInfoCpp backend_;
  bool is_root_ = false;

  mutable std::mutex mu_;
  std::set<std::string> known_tunnels_;

 public:
  // Override the sysfs root for testing.
  void SetSysfsRootForTesting(const std::string& root) { sysfs_root_ = root; }
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_WG_BACKEND_H_
