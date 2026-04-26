#ifndef FLUTTER_WIREGUARD_HELPER_TUNNEL_SERVICE_H_
#define FLUTTER_WIREGUARD_HELPER_TUNNEL_SERVICE_H_

#include <string>

namespace flutter_wireguard {

// Runs the per-tunnel SCM service body. `conf_path_utf16` is the path the
// broker passed via the service ImagePath. Returns process exit code.
int RunTunnelService(const std::wstring& conf_path);

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_HELPER_TUNNEL_SERVICE_H_
