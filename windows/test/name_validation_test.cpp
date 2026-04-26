#include <gtest/gtest.h>

#include "name_validator.h"

using flutter_wireguard::IsValidTunnelName;

TEST(IsValidTunnelName, AcceptsTypicalInterfaceNames) {
  EXPECT_TRUE(IsValidTunnelName("wg0"));
  EXPECT_TRUE(IsValidTunnelName("WG0"));
  EXPECT_TRUE(IsValidTunnelName("wg-vpn.1"));
  EXPECT_TRUE(IsValidTunnelName("wg_corporate"));
  EXPECT_TRUE(IsValidTunnelName("a"));
  EXPECT_TRUE(IsValidTunnelName("aaaaaaaaaaaaaaa"));  // 15 chars
  EXPECT_TRUE(IsValidTunnelName("foo=bar+baz"));
}

TEST(IsValidTunnelName, RejectsInvalid) {
  EXPECT_FALSE(IsValidTunnelName(""));
  EXPECT_FALSE(IsValidTunnelName("aaaaaaaaaaaaaaaa"));  // 16 chars
  EXPECT_FALSE(IsValidTunnelName("."));
  EXPECT_FALSE(IsValidTunnelName(".."));
  EXPECT_FALSE(IsValidTunnelName("../etc"));
  EXPECT_FALSE(IsValidTunnelName("wg 0"));
  EXPECT_FALSE(IsValidTunnelName("wg/0"));
  EXPECT_FALSE(IsValidTunnelName("wg\\0"));
  EXPECT_FALSE(IsValidTunnelName("wg\n"));
  EXPECT_FALSE(IsValidTunnelName("wg;rm"));
  EXPECT_FALSE(IsValidTunnelName(std::string("wg\0null", 7)));
}
