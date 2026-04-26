// Persistent privileged session.
//
// Many WireGuard operations on Linux need CAP_NET_ADMIN. Spawning `pkexec`
// for every call would prompt the user repeatedly (once per Start, Stop,
// Status...). This class establishes a single elevated `pkexec sh` child on
// the first request and reuses it for every subsequent privileged operation.
//
// The protocol over stdin/stdout is line-oriented:
//   parent -> child:   <OP>\n<ARG1>\n<ARG2>\n
//   child  -> parent:  <merged stdout+stderr>\n__FWG_END__ <exit_code>\n
//
// All arguments are strict, plugin-controlled values:
//   * iface names pass IsValidName() (max 15 chars, [A-Za-z0-9_=+.-]).
//   * config paths live under XDG_RUNTIME_DIR/flutter_wireguard/<iface>.conf.
//   * userspace impl is one of {wireguard-go, boringtun-cli, boringtun}.
// None of these can break the shell loop — but to be safe the loop double
// quotes every argument and the OP names are matched against a whitelist.
#ifndef FLUTTER_WIREGUARD_PRIVILEGED_SESSION_H_
#define FLUTTER_WIREGUARD_PRIVILEGED_SESSION_H_

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "process_runner.h"

namespace flutter_wireguard {

class PrivilegedSession {
 public:
  virtual ~PrivilegedSession() = default;

  // `wg show <iface> dump`. Used for handshake timestamps; rx/tx are read
  // from sysfs in the unprivileged path.
  virtual ProcessResult ShowDump(const std::string& iface) = 0;

  // `[WG_QUICK_USERSPACE_IMPLEMENTATION=<impl>] wg-quick up <conf_path>`.
  // Pass an empty string for `userspace_impl` to use the kernel module.
  virtual ProcessResult WgQuickUp(const std::string& conf_path,
                                  const std::string& userspace_impl) = 0;

  // `wg-quick down <conf_path>`. Best-effort.
  virtual ProcessResult WgQuickDown(const std::string& conf_path) = 0;
};

// Real impl: spawns pkexec sh on first use and keeps the pipe open.
// If the process is already root no elevation happens at all and each call
// runs the requested binary directly (one prompt is replaced with zero).
class RealPrivilegedSession : public PrivilegedSession {
 public:
  // `runner` is used to (a) probe for `pkexec` availability and (b) run the
  // direct, non-elevated commands when this process already runs as root.
  explicit RealPrivilegedSession(std::shared_ptr<ProcessRunner> runner);
  ~RealPrivilegedSession() override;

  ProcessResult ShowDump(const std::string& iface) override;
  ProcessResult WgQuickUp(const std::string& conf_path,
                          const std::string& userspace_impl) override;
  ProcessResult WgQuickDown(const std::string& conf_path) override;

 private:
  // Lazily spawn the `pkexec sh -c <loop>` child. Returns true on success.
  // Holds session_mu_ for the lifetime of the call.
  bool EnsureSession();

  // Send (op, arg1, arg2) and read the reply up to the __FWG_END__ marker.
  // Auto-recovers if the child died (e.g. user hit Cancel last time).
  ProcessResult SendOp(const std::string& op,
                       const std::string& arg1,
                       const std::string& arg2);

  void TeardownLocked();

  std::shared_ptr<ProcessRunner> runner_;
  bool is_root_;
  // Argv prefix used to acquire privileges, e.g. {"pkexec"} or
  // {"flatpak-spawn","--host","pkexec"}. Empty => use the default "pkexec".
  // Set from FLUTTER_WIREGUARD_ELEVATE in the ctor; see .cc for the contract.
  std::vector<std::string> elevate_prefix_;

  std::mutex session_mu_;        // serialises access to fds / child
  pid_t child_pid_ = -1;
  int   child_stdin_fd_  = -1;   // we write to this
  int   child_stdout_fd_ = -1;   // we read from this (stdout+stderr merged)
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_PRIVILEGED_SESSION_H_
