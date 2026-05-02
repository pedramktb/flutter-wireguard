#include "wg_backend.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "name_validator.h"

namespace flutter_wireguard {

namespace {

// Splits `s` on `sep` into a vector. Empty trailing fields are preserved.
std::vector<std::string> Split(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) { out.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  out.push_back(cur);
  return out;
}

bool ParseI64(const std::string& s, int64_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  errno = 0;
  long long v = std::strtoll(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || (*end != '\0' && *end != '\n')) return false;
  *out = static_cast<int64_t>(v);
  return true;
}

}  // namespace

bool WgBackend::ReadSysfsCounters(const std::string& name,
                                  int64_t* rx,
                                  int64_t* tx,
                                  const std::string& sysfs_root) {
  std::filesystem::path base =
      std::filesystem::path(sysfs_root) / name / "statistics";
  std::error_code ec;
  if (!std::filesystem::exists(base, ec)) return false;

  auto read_one = [&](const char* file, int64_t* out) -> bool {
    std::ifstream f(base / file);
    if (!f) return false;
    std::string s;
    std::getline(f, s);
    return ParseI64(s, out);
  };
  int64_t r = 0, t = 0;
  if (!read_one("rx_bytes", &r) || !read_one("tx_bytes", &t)) return false;
  *rx = r;
  *tx = t;
  return true;
}

bool WgBackend::IsValidName(const std::string& name) {
  return ::flutter_wireguard::IsValidTunnelName(name);
}

TunnelStatusCpp WgBackend::ParseWgShowDump(const std::string& name,
                                           const std::string& dump_stdout) {
  TunnelStatusCpp s;
  s.name = name;
  if (dump_stdout.empty()) {
    s.state = TunnelStateCpp::kDown;
    return s;
  }

  // Format (tab-separated):
  //   line 1 (interface): private-key  public-key  listen-port  fwmark
  //   line N+ (peers):    public-key  preshared  endpoint  allowed-ips
  //                       latest-handshake  rx-bytes  tx-bytes  keepalive
  std::stringstream ss(dump_stdout);
  std::string line;
  bool first = true;
  bool any_peer = false;
  while (std::getline(ss, line)) {
    if (line.empty()) continue;
    if (first) { first = false; continue; }
    auto parts = Split(line, '\t');
    if (parts.size() < 8) continue;
    any_peer = true;
    int64_t hs = 0, rx = 0, tx = 0;
    ParseI64(parts[4], &hs);
    ParseI64(parts[5], &rx);
    ParseI64(parts[6], &tx);
    if (hs * 1000 > s.handshake) s.handshake = hs * 1000;  // -> milliseconds
    s.rx += rx;
    s.tx += tx;
  }
  // Even with zero peers, a successful dump means the interface exists ⇒ UP.
  s.state = TunnelStateCpp::kUp;
  (void)any_peer;
  return s;
}

WgBackend::WgBackend(std::unique_ptr<ProcessRunner> runner,
                     std::string config_dir,
                     std::unique_ptr<PrivilegedSession> elevated)
    : runner_(std::move(runner)),
      elevated_(std::move(elevated)),
      config_dir_(std::move(config_dir)) {
  if (!elevated_) {
    // Default: build a real pkexec-backed session sharing our ProcessRunner.
    // We hand the session a non-owning view of runner_ via a shared_ptr alias
    // ctor so it stays alive as long as the backend.
    std::shared_ptr<ProcessRunner> shared_view(std::shared_ptr<ProcessRunner>{},
                                               runner_.get());
    elevated_ = std::make_unique<RealPrivilegedSession>(std::move(shared_view));
  }
  if (config_dir_.empty()) {
    // Per-user runtime directory (XDG_RUNTIME_DIR is rwx by uid only).
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    std::filesystem::path base;
    if (xdg != nullptr && *xdg != '\0') {
      base = std::filesystem::path(xdg) / "flutter_wireguard";
    } else {
      // Fallback: namespace by euid so distinct users on a shared system
      // cannot collide / clobber each other's configs in /tmp.
      base = std::filesystem::path("/tmp") /
             ("flutter_wireguard-" + std::to_string(geteuid()));
    }
    config_dir_ = base.string();
  }
  std::error_code ec;
  std::filesystem::create_directories(config_dir_, ec);
  if (ec) {
    throw std::runtime_error("failed to create config dir " + config_dir_ +
                             ": " + ec.message());
  }
  if (::chmod(config_dir_.c_str(), 0700) != 0) {
    throw std::runtime_error("failed to chmod 0700 " + config_dir_ + ": " +
                             std::strerror(errno));
  }
  // Refuse to use the dir if it is not owned by us or is group/world accessible
  // (mitigates symlink attacks when falling back to /tmp).
  struct stat st {};
  if (::lstat(config_dir_.c_str(), &st) != 0) {
    throw std::runtime_error("failed to stat " + config_dir_ + ": " +
                             std::strerror(errno));
  }
  if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error("refusing to use insecure config dir " +
                             config_dir_);
  }

  is_root_ = (geteuid() == 0);
  DetectBackend();
}

bool WgBackend::KernelModuleAvailable() const {
  std::error_code ec;
  // Already loaded, or built into the kernel (=y).
  if (std::filesystem::exists("/sys/module/wireguard", ec)) return true;
  // Loadable but not yet loaded — wg-quick will modprobe it on Start.
  // Look for wireguard.ko[.{xz,zst,gz}] under /lib/modules/<release>/.
  struct utsname uts {};
  if (::uname(&uts) != 0) return false;
  std::filesystem::path mod_root =
      std::filesystem::path("/lib/modules") / uts.release;
  if (!std::filesystem::exists(mod_root, ec)) return false;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(mod_root, ec)) {
    if (ec) break;
    const std::string fn = entry.path().filename().string();
    if (fn == "wireguard.ko" || fn.rfind("wireguard.ko.", 0) == 0) return true;
  }
  return false;
}

void WgBackend::DetectBackend() {
  const bool kernel_available = KernelModuleAvailable();
  const bool has_wg_quick = runner_->HasBinary("wg-quick");
  const bool has_wg = runner_->HasBinary("wg");
  const bool has_userspace =
      runner_->HasBinary("wireguard-go") ||
      runner_->HasBinary("boringtun-cli") ||
      runner_->HasBinary("boringtun");

  if (!has_wg_quick || !has_wg) {
    backend_.kind = BackendKindCpp::kUnknown;
    backend_.detail = "wireguard-tools not installed";
    return;
  }
  if (kernel_available) {
    backend_.kind = BackendKindCpp::kKernel;
    backend_.detail = "wg-quick (kernel)";
  } else if (has_userspace) {
    backend_.kind = BackendKindCpp::kUserspace;
    backend_.detail = "wg-quick (userspace)";
  } else {
    backend_.kind = BackendKindCpp::kUnknown;
    backend_.detail = "no kernel module and no userspace implementation found";
  }
}

std::string WgBackend::PickUserspaceImpl() const {
  if (backend_.kind != BackendKindCpp::kUserspace) return "";
  if (runner_->HasBinary("wireguard-go"))    return "wireguard-go";
  if (runner_->HasBinary("boringtun-cli"))   return "boringtun-cli";
  if (runner_->HasBinary("boringtun"))       return "boringtun";
  return "";
}

std::string WgBackend::WriteConfigFile(const std::string& name,
                                       const std::string& config) {
  std::filesystem::path p = std::filesystem::path(config_dir_) / (name + ".conf");
  // O_CREAT|O_TRUNC|O_WRONLY with mode 0600 atomically.
  int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    throw std::runtime_error(std::string("open ") + p.string() + ": " + std::strerror(errno));
  }
  size_t remaining = config.size();
  const char* data = config.data();
  while (remaining > 0) {
    ssize_t w = ::write(fd, data, remaining);
    if (w < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      throw std::runtime_error(std::string("write: ") + std::strerror(errno));
    }
    data += w;
    remaining -= static_cast<size_t>(w);
  }
  ::fchmod(fd, 0600);
  ::close(fd);
  return p.string();
}

void WgBackend::Start(const std::string& name, const std::string& config) {
  if (!IsValidName(name)) {
    throw std::invalid_argument("invalid interface name '" + name + "'");
  }
  if (backend_.kind == BackendKindCpp::kUnknown) {
    throw std::runtime_error(backend_.detail);
  }
  std::string cfg_path = WriteConfigFile(name, config);

  ProcessResult r = elevated_->WgQuickUp(cfg_path, PickUserspaceImpl());
  if (r.exit_code != 0) {
    throw std::runtime_error(
        "wg-quick up failed (" + std::to_string(r.exit_code) + "): " +
        (r.stderr_data.empty() ? r.stdout_data : r.stderr_data));
  }
  std::lock_guard<std::mutex> lock(mu_);
  known_tunnels_.insert(name);
}

void WgBackend::Stop(const std::string& name) {
  if (!IsValidName(name)) return;
  std::filesystem::path cfg = std::filesystem::path(config_dir_) / (name + ".conf");
  std::error_code ec;
  if (!std::filesystem::exists(cfg, ec)) return;

  // Best-effort; the caller treats Stop as idempotent.
  elevated_->WgQuickDown(cfg.string());
}

TunnelStatusCpp WgBackend::Status(const std::string& name) {
  if (!IsValidName(name)) {
    throw std::invalid_argument("invalid interface name '" + name + "'");
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (known_tunnels_.find(name) == known_tunnels_.end()) {
      throw std::runtime_error("tunnel '" + name + "' is unknown");
    }
  }

  // Source of truth #1: byte counters from /sys/class/net/<name>/statistics/.
  // World-readable for both kernel WireGuard and the wireguard-go TUN device.
  TunnelStatusCpp s;
  s.name = name;
  int64_t rx = 0, tx = 0;
  const bool iface_exists = ReadSysfsCounters(name, &rx, &tx, sysfs_root_);
  if (!iface_exists) {
    s.state = TunnelStateCpp::kDown;
    return s;
  }
  s.rx = rx;
  s.tx = tx;
  s.state = TunnelStateCpp::kUp;

  // Source of truth #2 (best-effort): `wg show <name> dump` for the latest
  // handshake and per-peer aggregated counters. Routed through the
  // PrivilegedSession so only the FIRST elevated op (typically Start) prompts
  // the user — the same pkexec child handles every subsequent call.
  ProcessResult r = elevated_->ShowDump(name);
  if (r.exit_code == 0) {
    TunnelStatusCpp parsed = ParseWgShowDump(name, r.stdout_data);
    s.handshake = parsed.handshake;
    if (parsed.rx > 0 || parsed.tx > 0) {
      s.rx = parsed.rx;
      s.tx = parsed.tx;
    }
  }
  return s;
}

std::vector<std::string> WgBackend::TunnelNames() const {
  std::lock_guard<std::mutex> lock(mu_);
  return std::vector<std::string>(known_tunnels_.begin(), known_tunnels_.end());
}

}  // namespace flutter_wireguard
