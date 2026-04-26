#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privileged_session.h"
#include "process_runner.h"
#include "wg_backend.h"

using flutter_wireguard::BackendKindCpp;
using flutter_wireguard::PrivilegedSession;
using flutter_wireguard::ProcessResult;
using flutter_wireguard::ProcessRunner;
using flutter_wireguard::TunnelStateCpp;
using flutter_wireguard::WgBackend;

namespace {

// Records every Run() call and returns scripted responses, indexed by argv[0]
// (or argv[1] when argv[0] is "pkexec") + first non-prefix arg.
class FakeRunner : public ProcessRunner {
 public:
  struct Call {
    std::vector<std::string> argv;
    std::map<std::string, std::string> env;
    std::optional<std::string> stdin_data;
  };

  std::vector<Call> calls;
  std::vector<ProcessResult> responses;        // popped front-to-back
  std::set<std::string> available_binaries;

  ProcessResult Run(const std::vector<std::string>& argv,
                    const std::map<std::string, std::string>& env,
                    const std::optional<std::string>& stdin_data) override {
    calls.push_back({argv, env, stdin_data});
    if (responses.empty()) return ProcessResult{0, "", ""};
    auto r = responses.front();
    responses.erase(responses.begin());
    return r;
  }

  bool HasBinary(const std::string& name) override {
    return available_binaries.count(name) > 0;
  }
};

// Records every privileged op and returns scripted responses. Stands in for
// RealPrivilegedSession so tests don't need pkexec.
class FakePrivilegedSession : public PrivilegedSession {
 public:
  struct ShowCall { std::string iface; };
  struct UpCall   { std::string conf_path; std::string userspace_impl; };
  struct DownCall { std::string conf_path; };

  std::vector<ShowCall> show_calls;
  std::vector<UpCall>   up_calls;
  std::vector<DownCall> down_calls;

  std::vector<ProcessResult> show_responses;
  std::vector<ProcessResult> up_responses;
  std::vector<ProcessResult> down_responses;

  ProcessResult ShowDump(const std::string& iface) override {
    show_calls.push_back({iface});
    return Pop(show_responses);
  }
  ProcessResult WgQuickUp(const std::string& conf_path,
                          const std::string& userspace_impl) override {
    up_calls.push_back({conf_path, userspace_impl});
    return Pop(up_responses);
  }
  ProcessResult WgQuickDown(const std::string& conf_path) override {
    down_calls.push_back({conf_path});
    return Pop(down_responses);
  }

 private:
  static ProcessResult Pop(std::vector<ProcessResult>& q) {
    if (q.empty()) return ProcessResult{0, "", ""};
    auto r = q.front();
    q.erase(q.begin());
    return r;
  }
};

}  // namespace

TEST(IsValidName, AcceptsTypicalInterfaceNames) {
  EXPECT_TRUE(WgBackend::IsValidName("wg0"));
  EXPECT_TRUE(WgBackend::IsValidName("home-vpn"));
  EXPECT_TRUE(WgBackend::IsValidName("a.b_c+d=e"));
  EXPECT_TRUE(WgBackend::IsValidName("123456789012345"));  // exactly 15 chars
}

TEST(IsValidName, RejectsInvalid) {
  EXPECT_FALSE(WgBackend::IsValidName(""));
  EXPECT_FALSE(WgBackend::IsValidName("."));
  EXPECT_FALSE(WgBackend::IsValidName(".."));
  EXPECT_FALSE(WgBackend::IsValidName("1234567890123456"));  // 16 chars
  EXPECT_FALSE(WgBackend::IsValidName("wg/0"));
  EXPECT_FALSE(WgBackend::IsValidName("wg 0"));
  EXPECT_FALSE(WgBackend::IsValidName("wg;rm -rf /"));
  EXPECT_FALSE(WgBackend::IsValidName("$(whoami)"));
}

TEST(ParseWgShowDump, EmptyOutputIsDown) {
  auto s = WgBackend::ParseWgShowDump("wg0", "");
  EXPECT_EQ(s.state, TunnelStateCpp::kDown);
  EXPECT_EQ(s.rx, 0);
  EXPECT_EQ(s.tx, 0);
  EXPECT_EQ(s.handshake, 0);
  EXPECT_EQ(s.name, "wg0");
}

TEST(ParseWgShowDump, AggregatesPeerStats) {
  // tab-separated fields. Iface line then two peer lines.
  const std::string out =
      "PRIV\tPUB\t51820\toff\n"
      "PEER1\t(none)\t1.2.3.4:5\t10.0.0.0/24\t1700000000\t100\t200\t25\n"
      "PEER2\t(none)\t6.7.8.9:5\t10.0.1.0/24\t1700000123\t300\t400\t25\n";
  auto s = WgBackend::ParseWgShowDump("wg0", out);
  EXPECT_EQ(s.state, TunnelStateCpp::kUp);
  EXPECT_EQ(s.rx, 400);
  EXPECT_EQ(s.tx, 600);
  EXPECT_EQ(s.handshake, int64_t{1700000123} * 1000);
}

TEST(ParseWgShowDump, MalformedLinesIgnored) {
  const std::string out =
      "PRIV\tPUB\t51820\toff\n"
      "garbage line with no tabs\n"
      "PEER\t(none)\tep\tips\t100\t1\t2\t0\n";
  auto s = WgBackend::ParseWgShowDump("wg0", out);
  EXPECT_EQ(s.rx, 1);
  EXPECT_EQ(s.tx, 2);
}

class WgBackendIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto runner_uptr = std::make_unique<FakeRunner>();
    runner = runner_uptr.get();
    runner->available_binaries = {"wg", "wg-quick", "pkexec", "wireguard-go"};
    auto session_uptr = std::make_unique<FakePrivilegedSession>();
    session = session_uptr.get();
    sysfs_root = "/tmp/fwg-test-sysfs-" + std::to_string(::getpid());
    std::filesystem::remove_all(sysfs_root);
    backend = std::make_unique<WgBackend>(
        std::move(runner_uptr),
        "/tmp/fwg-test-" + std::to_string(::getpid()),
        std::move(session_uptr));
    backend->SetSysfsRootForTesting(sysfs_root);
  }
  void TearDown() override { std::filesystem::remove_all(sysfs_root); }

  // Writes /tmp/fwg-test-sysfs-<pid>/<iface>/statistics/{rx,tx}_bytes.
  void WriteSysfsCounters(const std::string& iface, int64_t rx, int64_t tx) {
    auto dir = std::filesystem::path(sysfs_root) / iface / "statistics";
    std::filesystem::create_directories(dir);
    std::ofstream(dir / "rx_bytes") << rx << "\n";
    std::ofstream(dir / "tx_bytes") << tx << "\n";
  }

  FakeRunner* runner;                       // owned by backend
  FakePrivilegedSession* session;           // owned by backend
  std::string sysfs_root;
  std::unique_ptr<WgBackend> backend;
};

TEST_F(WgBackendIntegrationTest, DetectsBackend) {
  // No /sys/module/wireguard in the test env (almost certainly), and we don't
  // expose a userspace binary either, so the result is well-defined: either
  // userspace if the host actually has a kernel module loaded, or unknown
  // otherwise. We only assert detail is non-empty.
  EXPECT_FALSE(backend->Backend().detail.empty());
}

TEST_F(WgBackendIntegrationTest, StartRejectsInvalidName) {
  EXPECT_THROW(backend->Start("bad name", "[Interface]"), std::invalid_argument);
}

TEST_F(WgBackendIntegrationTest, StartInvokesWgQuickWithConfigFile) {
  session->up_responses.push_back({0, "", ""});  // wg-quick up succeeds
  backend->Start("wg0", "[Interface]\nPrivateKey = abc\n");

  ASSERT_EQ(session->up_calls.size(), 1u);
  EXPECT_NE(session->up_calls[0].conf_path.find("/wg0.conf"),
            std::string::npos);

  // Tunnel is now in TunnelNames().
  auto names = backend->TunnelNames();
  EXPECT_EQ(names.size(), 1u);
  EXPECT_EQ(names[0], "wg0");
}

TEST_F(WgBackendIntegrationTest, StartPropagatesErrorMessage) {
  session->up_responses.push_back({1, "", "boom"});
  EXPECT_THROW(backend->Start("wg0", ""), std::runtime_error);
}

TEST_F(WgBackendIntegrationTest, StatusRejectsUnknownTunnel) {
  EXPECT_THROW(backend->Status("never-started"), std::runtime_error);
}

TEST_F(WgBackendIntegrationTest, StatusReturnsParsedDump) {
  // Start first so the tunnel is "known".
  session->up_responses.push_back({0, "", ""});  // start
  backend->Start("wg0", "");
  WriteSysfsCounters("wg0", /*rx=*/0, /*tx=*/0);  // interface exists
  session->show_responses.push_back({0,
      "PRIV\tPUB\t51820\toff\n"
      "PEER\t(none)\tep\tips\t12345\t10\t20\t0\n", ""});
  auto s = backend->Status("wg0");
  EXPECT_EQ(s.state, TunnelStateCpp::kUp);
  // wg-reported counters are preferred over sysfs when non-zero.
  EXPECT_EQ(s.rx, 10);
  EXPECT_EQ(s.tx, 20);
  EXPECT_EQ(s.handshake, 12345 * 1000);
  ASSERT_EQ(session->show_calls.size(), 1u);
  EXPECT_EQ(session->show_calls[0].iface, "wg0");
}

TEST_F(WgBackendIntegrationTest, StopIsIdempotentOnUnknownTunnel) {
  // No exception, no Run() call (no config file written).
  backend->Stop("never-started");
}

TEST_F(WgBackendIntegrationTest, StatusFallsBackToSysfsCountersWithoutWgShow) {
  session->up_responses.push_back({0, "", ""});  // start
  backend->Start("wg0", "");
  WriteSysfsCounters("wg0", /*rx=*/4096, /*tx=*/2048);
  // `wg show` fails — sysfs counters still surface.
  session->show_responses.push_back({1, "", "Operation not permitted"});

  auto s = backend->Status("wg0");
  EXPECT_EQ(s.state, TunnelStateCpp::kUp);
  EXPECT_EQ(s.rx, 4096);
  EXPECT_EQ(s.tx, 2048);
  EXPECT_EQ(s.handshake, 0);
}

TEST_F(WgBackendIntegrationTest, StatusReportsDownWhenInterfaceMissing) {
  session->up_responses.push_back({0, "", ""});  // start
  backend->Start("wg0", "");
  // No sysfs entry written ⇒ interface absent ⇒ DOWN. wg show should not even
  // be attempted in this case.
  session->show_calls.clear();
  auto s = backend->Status("wg0");
  EXPECT_EQ(s.state, TunnelStateCpp::kDown);
  EXPECT_TRUE(session->show_calls.empty());
}

// All privileged ops are routed through PrivilegedSession (one pkexec
// prompt for the whole app session) — no fork-and-exec of pkexec per call.
TEST_F(WgBackendIntegrationTest, AllPrivilegedOpsGoThroughSession) {
  session->up_responses.push_back({0, "", ""});
  backend->Start("wg0", "");
  WriteSysfsCounters("wg0", 1, 2);
  // 5 status polls -> 5 ShowDump calls on the same session, never pkexec.
  for (int i = 0; i < 5; ++i) {
    session->show_responses.push_back({0, "", ""});
    backend->Status("wg0");
  }
  EXPECT_EQ(session->show_calls.size(), 5u);
  EXPECT_EQ(session->up_calls.size(), 1u);
  // Stop also goes through the session.
  backend->Stop("wg0");
  EXPECT_EQ(session->down_calls.size(), 1u);
  // The unprivileged `runner` is never used to exec pkexec.
  for (const auto& c : runner->calls) {
    for (const auto& a : c.argv) EXPECT_NE(a, "pkexec");
  }
}
