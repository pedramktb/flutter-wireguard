#include <gtest/gtest.h>

#include <vector>

#include "ipc_protocol.h"

namespace ipc = flutter_wireguard::ipc;

TEST(IpcProtocol, BuildAndParseFrameRoundTrip) {
  ipc::Writer payload;
  payload.U8(ipc::kStatusOk);
  payload.Str("wg0");
  payload.U8(2);
  payload.I64(123);
  payload.I64(456);
  payload.I64(1700000000123);

  std::vector<uint8_t> bytes = payload.Take();
  std::vector<uint8_t> frame =
      ipc::BuildFrame(ipc::kOpStatus, 42, ipc::kFlagNone, bytes);

  // [u32 total_len][u32 op][u32 seq][u8 flags][payload...]
  ASSERT_GE(frame.size(), 13u);
  uint32_t total = static_cast<uint32_t>(frame[0]) |
                   (static_cast<uint32_t>(frame[1]) << 8) |
                   (static_cast<uint32_t>(frame[2]) << 16) |
                   (static_cast<uint32_t>(frame[3]) << 24);
  EXPECT_EQ(total, 9u + bytes.size());
  EXPECT_EQ(total + 4u, frame.size());

  ipc::Reader r(frame.data() + 4, frame.size() - 4);
  EXPECT_EQ(r.U32(), static_cast<uint32_t>(ipc::kOpStatus));
  EXPECT_EQ(r.U32(), 42u);
  EXPECT_EQ(r.U8(), ipc::kFlagNone);

  EXPECT_EQ(r.U8(), ipc::kStatusOk);
  EXPECT_EQ(r.Str(), "wg0");
  EXPECT_EQ(r.U8(), 2u);
  EXPECT_EQ(r.I64(), 123);
  EXPECT_EQ(r.I64(), 456);
  EXPECT_EQ(r.I64(), 1700000000123);
}

TEST(IpcProtocol, ReaderShortReadThrows) {
  std::vector<uint8_t> tiny = {0x05, 0x00};
  ipc::Reader r(tiny.data(), tiny.size());
  EXPECT_THROW(r.U32(), std::runtime_error);
}

TEST(IpcProtocol, RejectsOversizedString) {
  std::vector<uint8_t> bad(8);
  // Length prefix = 0xFFFFFFFF (way over kMaxConfigBytes).
  bad[0] = bad[1] = bad[2] = bad[3] = 0xFF;
  ipc::Reader r(bad.data(), bad.size());
  EXPECT_THROW(r.Str(), std::length_error);
}

TEST(IpcProtocol, BuildFrameRefusesOversize) {
  std::vector<uint8_t> huge(ipc::kMaxFrameBytes);  // headroom of 9 still over
  EXPECT_THROW(ipc::BuildFrame(ipc::kOpStart, 1, 0, huge), std::length_error);
}
