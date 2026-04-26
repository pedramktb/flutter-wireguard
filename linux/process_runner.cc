#include "process_runner.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>

extern char** environ;

namespace flutter_wireguard {

namespace {

// Reads everything from `fd` until EOF. Closes `fd`.
std::string ReadAll(int fd) {
  std::string out;
  std::array<char, 4096> buf{};
  while (true) {
    ssize_t n = read(fd, buf.data(), buf.size());
    if (n > 0) {
      out.append(buf.data(), static_cast<size_t>(n));
    } else if (n == 0) {
      break;
    } else if (errno == EINTR) {
      continue;
    } else {
      break;
    }
  }
  close(fd);
  return out;
}

}  // namespace

ProcessResult RealProcessRunner::Run(
    const std::vector<std::string>& argv,
    const std::map<std::string, std::string>& env_extra,
    const std::optional<std::string>& stdin_data) {
  ProcessResult result;
  if (argv.empty()) return result;

  int stdin_pipe[2] = {-1, -1};
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
    result.stderr_data = "pipe() failed";
    return result;
  }

  // Build argv (NULL-terminated char* array).
  std::vector<char*> c_argv;
  c_argv.reserve(argv.size() + 1);
  for (const auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
  c_argv.push_back(nullptr);

  // Build merged env. Copy parent environment then overlay env_extra.
  std::vector<std::string> env_strings;
  for (char** e = environ; *e != nullptr; ++e) env_strings.emplace_back(*e);
  for (const auto& kv : env_extra) {
    // Replace any existing entry with the same key.
    const std::string prefix = kv.first + "=";
    env_strings.erase(
        std::remove_if(env_strings.begin(), env_strings.end(),
                       [&](const std::string& s) { return s.rfind(prefix, 0) == 0; }),
        env_strings.end());
    env_strings.emplace_back(prefix + kv.second);
  }
  std::vector<char*> c_env;
  c_env.reserve(env_strings.size() + 1);
  for (auto& s : env_strings) c_env.push_back(s.data());
  c_env.push_back(nullptr);

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, stdin_pipe[0], STDIN_FILENO);
  posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, stderr_pipe[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, stdin_pipe[1]);
  posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, stderr_pipe[0]);

  pid_t pid = -1;
  int spawn_rc = posix_spawnp(&pid, c_argv[0], &actions, nullptr,
                              c_argv.data(), c_env.data());
  posix_spawn_file_actions_destroy(&actions);

  // Close child ends in the parent.
  close(stdin_pipe[0]);
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  if (spawn_rc != 0) {
    close(stdin_pipe[1]);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    result.stderr_data = std::string("posix_spawnp failed: ") + std::strerror(spawn_rc);
    return result;
  }

  // Write stdin (if any) then close.
  if (stdin_data.has_value() && !stdin_data->empty()) {
    const char* p = stdin_data->data();
    size_t remaining = stdin_data->size();
    while (remaining > 0) {
      ssize_t w = write(stdin_pipe[1], p, remaining);
      if (w < 0) {
        if (errno == EINTR) continue;
        break;
      }
      p += w;
      remaining -= static_cast<size_t>(w);
    }
  }
  close(stdin_pipe[1]);

  // Drain stdout/stderr in series — both have their own pipe buffer (typically
  // 64 KiB) which is far more than wg-quick / wg ever produce.
  result.stdout_data = ReadAll(stdout_pipe[0]);
  result.stderr_data = ReadAll(stderr_pipe[0]);

  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) break;
  }
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = 128 + WTERMSIG(status);
  } else {
    result.exit_code = -1;
  }
  return result;
}

bool RealProcessRunner::HasBinary(const std::string& name) {
  const char* path = getenv("PATH");
  if (path == nullptr) return false;
  std::stringstream ss(path);
  std::string dir;
  while (std::getline(ss, dir, ':')) {
    if (dir.empty()) continue;
    std::filesystem::path candidate = std::filesystem::path(dir) / name;
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) &&
        access(candidate.c_str(), X_OK) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace flutter_wireguard
