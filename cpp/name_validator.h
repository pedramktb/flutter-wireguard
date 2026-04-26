// Header-only tunnel-name validator shared between Linux and Windows
// implementations. Mirrored by the Kotlin and Swift backends so every
// platform refuses the same set of inputs *before* any of them touches a
// shell, kernel API, registry key, or filesystem path.
//
// Rules (kept identical across platforms):
//   * length 1..15 (Linux IFNAMSIZ-1; Windows wireguard-nt also caps adapter
//     names at 15 wide chars in practice).
//   * characters: [A-Za-z0-9_=+.-]
//   * not "." or ".."
#ifndef FLUTTER_WIREGUARD_NAME_VALIDATOR_H_
#define FLUTTER_WIREGUARD_NAME_VALIDATOR_H_

#include <cstddef>
#include <string>

namespace flutter_wireguard {

inline constexpr std::size_t kMaxTunnelNameLen = 15;

inline bool IsValidTunnelName(const std::string& name) {
  if (name.empty() || name.size() > kMaxTunnelNameLen) return false;
  if (name == "." || name == "..") return false;
  for (char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '=' ||
                    c == '+' || c == '.' || c == '-';
    if (!ok) return false;
  }
  return true;
}

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_NAME_VALIDATOR_H_
