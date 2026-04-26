// Lightweight process runner abstraction for the Linux plugin.
//
// The default implementation forks/execvps a child process with a chosen argv,
// environment, and optional stdin payload, and captures stdout/stderr. The
// abstraction lets tests substitute a fake runner without touching real
// system binaries.
#ifndef FLUTTER_WIREGUARD_PROCESS_RUNNER_H_
#define FLUTTER_WIREGUARD_PROCESS_RUNNER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace flutter_wireguard {

struct ProcessResult {
  int exit_code = -1;        // 0 on success, -1 if the process could not be spawned.
  std::string stdout_data;
  std::string stderr_data;
};

class ProcessRunner {
 public:
  virtual ~ProcessRunner() = default;
  virtual ProcessResult Run(
      const std::vector<std::string>& argv,
      const std::map<std::string, std::string>& env_extra,
      const std::optional<std::string>& stdin_data) = 0;

  // Returns true if `name` exists on the user's PATH.
  virtual bool HasBinary(const std::string& name) = 0;
};

// fork()/execvp()-based runner. Inherits the parent's environment and merges
// `env_extra` on top of it.
class RealProcessRunner : public ProcessRunner {
 public:
  ProcessResult Run(const std::vector<std::string>& argv,
                    const std::map<std::string, std::string>& env_extra,
                    const std::optional<std::string>& stdin_data) override;
  bool HasBinary(const std::string& name) override;
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_PROCESS_RUNNER_H_
