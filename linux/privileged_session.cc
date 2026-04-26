#include "privileged_session.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sstream>

extern char** environ;

namespace flutter_wireguard {

namespace {

constexpr const char* kEndMarker = "__FWG_END__";

// Splits a string on whitespace (space/tab). Empty input -> empty vector.
// Used to parse FLUTTER_WIREGUARD_ELEVATE into an argv prefix. We deliberately
// do NOT do shell quoting here — the env var is set by the embedding app, not
// by user input, and keeping the parser trivial avoids surprises.
std::vector<std::string> SplitWS(const std::string& s) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == ' ' || c == '\t') {
      if (!cur.empty()) { out.push_back(cur); cur.clear(); }
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

// Inline shell loop. Reads three lines (OP, ARG1, ARG2) per request, runs the
// matching command with stdout+stderr merged, then emits __FWG_END__ <ec>.
// All variables are double-quoted — args containing spaces are safe — and the
// OP is matched against a fixed allowlist so unexpected input cannot escape.
constexpr const char* kShellLoop = R"SHELL(
while IFS= read -r op && IFS= read -r a1 && IFS= read -r a2; do
  case "$op" in
    SHOW)    wg show "$a1" dump 2>&1 ;;
    UP)      wg-quick up "$a1" 2>&1 ;;
    UPENV)   WG_QUICK_USERSPACE_IMPLEMENTATION="$a1" wg-quick up "$a2" 2>&1 ;;
    DOWN)    wg-quick down "$a1" 2>&1 ;;
    *)       echo "unknown op: $op" >&2 ;;
  esac
  printf "%s %d\n" "__FWG_END__" "$?"
done
)SHELL";

bool WriteAll(int fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t w = ::write(fd, data.data() + off, data.size() - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<size_t>(w);
  }
  return true;
}

// Reads from fd until a line equal to "__FWG_END__ <num>\n" is encountered.
// Returns true on success and sets *body to all bytes BEFORE the marker line,
// *exit_code to the parsed integer.
bool ReadUntilMarker(int fd, std::string* body, int* exit_code) {
  std::string buf;
  char chunk[4096];
  while (true) {
    ssize_t n = ::read(fd, chunk, sizeof(chunk));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;  // EOF: child died
    buf.append(chunk, chunk + n);

    // Look for the marker on its own line.
    size_t pos = 0;
    while (true) {
      size_t nl = buf.find('\n', pos);
      if (nl == std::string::npos) break;
      const std::string line = buf.substr(pos, nl - pos);
      if (line.rfind(kEndMarker, 0) == 0) {
        // Body is everything before this line.
        *body = buf.substr(0, pos);
        // Exit code follows the marker (after a single space).
        const std::string tail = line.substr(std::strlen(kEndMarker));
        try {
          *exit_code = std::stoi(tail);
        } catch (...) {
          *exit_code = -1;
        }
        return true;
      }
      pos = nl + 1;
    }
  }
}

}  // namespace

RealPrivilegedSession::RealPrivilegedSession(std::shared_ptr<ProcessRunner> runner)
    : runner_(std::move(runner)), is_root_(::geteuid() == 0) {
  // Allow the embedding app to override how we acquire privileges. This is
  // the hook downstream packagers (flatpak, snap, system-service apps) use:
  //
  //   unset / ""     -> default: spawn `pkexec sh -c <loop>`.
  //   "none"         -> skip elevation entirely (process must already have
  //                     CAP_NET_ADMIN; appropriate for system-helper apps).
  //   anything else  -> whitespace-split argv prefix, e.g.
  //                     "flatpak-spawn --host pkexec" to escape a flatpak
  //                     sandbox, or "sudo -A" for a custom askpass.
  if (const char* override_env = std::getenv("FLUTTER_WIREGUARD_ELEVATE")) {
    std::string v = override_env;
    if (v == "none") {
      // Treat exactly like the root path: one-shot direct exec, no prompt.
      is_root_ = true;
    } else if (!v.empty()) {
      elevate_prefix_ = SplitWS(v);
    }
  }
}

RealPrivilegedSession::~RealPrivilegedSession() {
  std::lock_guard<std::mutex> lock(session_mu_);
  TeardownLocked();
}

void RealPrivilegedSession::TeardownLocked() {
  if (child_stdin_fd_  >= 0) { ::close(child_stdin_fd_);  child_stdin_fd_  = -1; }
  if (child_stdout_fd_ >= 0) { ::close(child_stdout_fd_); child_stdout_fd_ = -1; }
  if (child_pid_ > 0) {
    ::kill(child_pid_, SIGTERM);
    int status = 0;
    ::waitpid(child_pid_, &status, 0);
    child_pid_ = -1;
  }
}

bool RealPrivilegedSession::EnsureSession() {
  if (child_pid_ > 0 && child_stdin_fd_ >= 0 && child_stdout_fd_ >= 0) {
    return true;
  }
  TeardownLocked();

  // Resolve the elevation argv. Default is just ["pkexec"]; the env-var
  // override (parsed in the ctor) takes precedence. We only probe for the
  // default "pkexec" binary — a custom prefix is the embedder's responsibility.
  std::vector<std::string> elev = elevate_prefix_;
  if (elev.empty()) {
    if (!runner_->HasBinary("pkexec")) return false;
    elev = {"pkexec"};
  }

  int in_pipe[2];   // parent writes child stdin
  int out_pipe[2];  // parent reads child stdout
  if (::pipe(in_pipe) < 0)  return false;
  if (::pipe(out_pipe) < 0) {
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    return false;
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  // Child stdin <- read end of in_pipe.
  posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
  // Child stdout/stderr -> write end of out_pipe.
  posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDERR_FILENO);
  // Close the parent ends in the child.
  posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
  posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, in_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, out_pipe[1]);

  // <elev...> sh -c <loop>
  std::vector<std::string> args = elev;
  args.push_back("sh");
  args.push_back("-c");
  args.push_back(kShellLoop);
  std::vector<char*> argv;
  for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
  argv.push_back(nullptr);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, elev[0].c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);

  // Close the child-side ends in the parent regardless.
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);

  if (rc != 0) {
    ::close(in_pipe[1]);
    ::close(out_pipe[0]);
    return false;
  }

  child_pid_        = pid;
  child_stdin_fd_   = in_pipe[1];
  child_stdout_fd_  = out_pipe[0];
  return true;
}

ProcessResult RealPrivilegedSession::SendOp(const std::string& op,
                                            const std::string& arg1,
                                            const std::string& arg2) {
  std::lock_guard<std::mutex> lock(session_mu_);

  if (is_root_) {
    // Root path: just shell out directly via the existing ProcessRunner.
    // This avoids pkexec entirely.
    std::vector<std::string> argv;
    std::map<std::string, std::string> env;
    if (op == "SHOW")        argv = {"wg", "show", arg1, "dump"};
    else if (op == "UP")     argv = {"wg-quick", "up", arg1};
    else if (op == "UPENV") {
      argv = {"wg-quick", "up", arg2};
      env["WG_QUICK_USERSPACE_IMPLEMENTATION"] = arg1;
    }
    else if (op == "DOWN")   argv = {"wg-quick", "down", arg1};
    else                     return {-1, "", "unknown op " + op};
    return runner_->Run(argv, env, std::nullopt);
  }

  for (int attempt = 0; attempt < 2; ++attempt) {
    if (!EnsureSession()) {
      return {-1, "", "privilege elevation is not available (pkexec missing? "
                      "set FLUTTER_WIREGUARD_ELEVATE to override)"};
    }
    std::string payload = op + "\n" + arg1 + "\n" + arg2 + "\n";
    if (!WriteAll(child_stdin_fd_, payload)) {
      TeardownLocked();
      continue;  // child probably died — retry once with a fresh session
    }
    std::string body;
    int ec = -1;
    if (!ReadUntilMarker(child_stdout_fd_, &body, &ec)) {
      TeardownLocked();
      continue;
    }
    return {ec, body, ""};
  }
  return {-1, "", "elevated session lost"};
}

ProcessResult RealPrivilegedSession::ShowDump(const std::string& iface) {
  return SendOp("SHOW", iface, "");
}

ProcessResult RealPrivilegedSession::WgQuickUp(const std::string& conf_path,
                                               const std::string& userspace_impl) {
  if (userspace_impl.empty()) {
    return SendOp("UP", conf_path, "");
  }
  return SendOp("UPENV", userspace_impl, conf_path);
}

ProcessResult RealPrivilegedSession::WgQuickDown(const std::string& conf_path) {
  return SendOp("DOWN", conf_path, "");
}

}  // namespace flutter_wireguard
