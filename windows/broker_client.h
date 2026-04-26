#ifndef FLUTTER_WIREGUARD_BROKER_CLIENT_H_
#define FLUTTER_WIREGUARD_BROKER_CLIENT_H_

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace flutter_wireguard {

struct BrokerStatus {
  std::string name;
  uint8_t state = 0;  // 0=down, 1=toggle, 2=up
  int64_t rx = 0;
  int64_t tx = 0;
  int64_t handshake_ms = 0;
};

struct BrokerBackend {
  uint8_t kind = 2;  // 0=kernel, 1=userspace, 2=unknown
  std::string detail;
};

// Sync-style API on top of an async pipe loop. Each public method blocks until
// the broker replies; the pigeon-generated host-api glue is invoked on
// Flutter's platform-task-runner thread, which is fine to block briefly. For
// long ops (Start), the pigeon @async signature lets the Dart side stay
// responsive — we run the call from a worker thread (see BrokerClient::Run).
class BrokerClient {
 public:
  using StatusCallback = std::function<void(const BrokerStatus&)>;

  static BrokerClient& Instance();

  // Sets the callback invoked from a background thread whenever a status
  // event arrives. May be called before or after Start().
  void SetStatusCallback(StatusCallback cb);

  // Throws std::runtime_error on failure.
  void Start(const std::string& name, const std::string& config);
  void Stop(const std::string& name);
  BrokerStatus Status(const std::string& name);
  std::vector<std::string> TunnelNames();
  BrokerBackend Backend();

  // Tears the connection down (used by tests).
  void Shutdown();

  // Test seam: override the helper-exe path normally derived from the plugin
  // module location. Must be called before the first request.
  void SetHelperPathForTesting(std::wstring path) { helper_path_ = std::move(path); }

 private:
  BrokerClient() = default;
  ~BrokerClient();
  BrokerClient(const BrokerClient&) = delete;
  BrokerClient& operator=(const BrokerClient&) = delete;

  void EnsureConnected();
  std::wstring ResolveHelperPath();
  HANDLE LaunchBrokerAndConnect();
  void ReaderLoop();
  std::vector<uint8_t> Request(uint32_t op, const std::vector<uint8_t>& payload);

  std::mutex mu_;
  std::mutex write_mu_;     // serializes WriteFile on pipe_
  std::mutex connect_mu_;   // serializes EnsureConnected
  std::condition_variable cv_;
  HANDLE pipe_ = INVALID_HANDLE_VALUE;
  std::thread reader_;
  std::atomic<bool> stop_{false};
  uint32_t next_seq_ = 1;

  // Pending inflight request: seq -> response payload (incl. status byte).
  struct Pending {
    bool ready = false;
    std::vector<uint8_t> payload;
    std::string error;  // pipe-level error (broker disconnected etc.)
  };
  std::map<uint32_t, std::shared_ptr<Pending>> inflight_;

  StatusCallback status_cb_;
  std::wstring helper_path_;
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_BROKER_CLIENT_H_
