#ifndef FLUTTER_WIREGUARD_PIPE_SECURITY_H_
#define FLUTTER_WIREGUARD_PIPE_SECURITY_H_

#include <windows.h>

#include <memory>

namespace flutter_wireguard {

// Owns a SECURITY_ATTRIBUTES suitable for CreateNamedPipeW. The DACL grants
// FILE_GENERIC_READ|WRITE only to:
//   - the launching user (passed in as a SID),
//   - SYSTEM (so service-side diagnostics keep working),
//   - BUILTIN\Administrators.
// Everyone else is implicitly denied. No DENY ACEs are added — order matters.
class PipeSecurity {
 public:
  // `client_user_sid` is taken from the access token of the user the broker
  // was launched on behalf of (parent process / WTSGetActiveConsoleSessionId
  // user, depending on launch path). Ownership is borrowed; the caller keeps
  // it alive for the lifetime of this object.
  static std::unique_ptr<PipeSecurity> Create(PSID client_user_sid);

  ~PipeSecurity();

  PipeSecurity(const PipeSecurity&) = delete;
  PipeSecurity& operator=(const PipeSecurity&) = delete;

  SECURITY_ATTRIBUTES* sa() { return &sa_; }

 private:
  PipeSecurity() = default;

  SECURITY_ATTRIBUTES sa_{};
  PSECURITY_DESCRIPTOR sd_ = nullptr;
  PACL acl_ = nullptr;
  PSID admins_sid_ = nullptr;
  PSID system_sid_ = nullptr;
};

// Returns the SID of the user owning the active interactive console session,
// or nullptr on failure. The returned SID must be freed with LocalFree.
PSID GetActiveConsoleUserSid();

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_PIPE_SECURITY_H_
