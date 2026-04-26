#include <gtest/gtest.h>

#include "process_runner.h"

using flutter_wireguard::RealProcessRunner;

TEST(RealProcessRunner, EchoStdout) {
  RealProcessRunner r;
  auto result = r.Run({"/bin/sh", "-c", "printf hello"}, {}, std::nullopt);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_EQ(result.stdout_data, "hello");
  EXPECT_TRUE(result.stderr_data.empty());
}

TEST(RealProcessRunner, NonZeroExit) {
  RealProcessRunner r;
  auto result = r.Run({"/bin/sh", "-c", "exit 7"}, {}, std::nullopt);
  EXPECT_EQ(result.exit_code, 7);
}

TEST(RealProcessRunner, EnvOverrideTakesPrecedence) {
  RealProcessRunner r;
  // The variable would normally be unset; we set it via env_extra.
  auto result = r.Run({"/bin/sh", "-c", "printf %s \"$FWG_TEST_VAR\""},
                      {{"FWG_TEST_VAR", "ok"}}, std::nullopt);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_EQ(result.stdout_data, "ok");
}

TEST(RealProcessRunner, StdinIsForwarded) {
  RealProcessRunner r;
  auto result = r.Run({"/bin/sh", "-c", "cat"}, {}, std::string("payload"));
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_EQ(result.stdout_data, "payload");
}

TEST(RealProcessRunner, MissingBinary) {
  RealProcessRunner r;
  auto result = r.Run({"/this/binary/does/not/exist"}, {}, std::nullopt);
  EXPECT_NE(result.exit_code, 0);
}

TEST(RealProcessRunner, HasBinaryDetectsCommonTools) {
  RealProcessRunner r;
  EXPECT_TRUE(r.HasBinary("sh"));
  EXPECT_FALSE(r.HasBinary("definitely-not-on-path-xyz123"));
}
