# Vendored native dependencies

This directory contains prebuilt third-party WireGuard binaries that the
plugin loads at runtime via `LoadLibrary`. They are **not** linked at build
time — `windows/lib/{wireguard,tunnel}/{amd64,arm64}/*.dll` are bundled
verbatim and dropped next to the helper exe.

Update this file whenever you bump a version.

---

## wireguard-nt (`wireguard.dll`, `wireguard.h`)

| field      | value                                                              |
| ---------- | ------------------------------------------------------------------ |
| version    | **1.0**                                                            |
| source     | <https://download.wireguard.com/wireguard-nt/wireguard-nt-1.0.zip> |
| upstream   | <https://git.zx2c4.com/wireguard-nt/>                              |
| license    | MIT (see `wireguard/LICENSE.txt`)                                  |
| signed by  | Jason A. Donenfeld                                                 |
| updated    | 2026-04-26                                                         |

SHA-256:

```
40add3d0b47bee347fcad0f59a0a68ca3d98fb4f7aa90cc4e8ff76086219eca7  wireguard/amd64/wireguard.dll
31609ffeaa90fc026ac04c713d33cf2ecf827934aa595c5a239e4757f1e259d8  wireguard/arm64/wireguard.dll
c770ab9ff979c55d63693099592cd24fdea4272de57c9dfb669daf19725b2e60  wireguard/include/wireguard.h
```

ZIP archive (the file actually downloaded — pin this for reproducibility):

```
d44f53300e47b44c53e77ee4c495cf061d06b5739f28872432ee1596107a302d  wireguard-nt-1.0.zip
```

### How to update

```sh
curl -fLO https://download.wireguard.com/wireguard-nt/wireguard-nt-<VER>.zip
sha256sum wireguard-nt-<VER>.zip          # record in this file
unzip wireguard-nt-<VER>.zip
cp wireguard-nt/bin/amd64/wireguard.dll  windows/lib/wireguard/amd64/
cp wireguard-nt/bin/arm64/wireguard.dll  windows/lib/wireguard/arm64/
cp wireguard-nt/include/wireguard.h      windows/lib/wireguard/include/
cp wireguard-nt/LICENSE.txt              windows/lib/wireguard/LICENSE.txt
sha256sum windows/lib/wireguard/{amd64,arm64}/wireguard.dll \
         windows/lib/wireguard/include/wireguard.h          # update table above
```

---

## wireguard-windows embeddable tunnel (`tunnel.dll`, `tunnel.h`)

Source is pinned as a git submodule at
[`third_party/wireguard-windows`](../../third_party/wireguard-windows) — the
binaries here are built from that exact tree.

| field      | value                                                              |
| ---------- | ------------------------------------------------------------------ |
| version    | **v1.0.1**                                                         |
| submodule  | `third_party/wireguard-windows` @ `a4b7f47672b393698127ca14a58f5953bc8b5217` |
| upstream   | <https://git.zx2c4.com/wireguard-windows/about/embeddable-dll-service/> |
| license    | GPLv2 — loaded via `LoadLibrary`, never statically linked          |
| signed by  | n/a (rebuilt locally)                                              |
| amd64      | built 2026-04-26 from Linux via `x86_64-w64-mingw32-gcc` cross-compile |
| arm64      | built 2026-04-26 from Linux via `aarch64-w64-mingw32-clang` (llvm-mingw) |

SHA-256:

```
12ee8e6a56bf1b36078ca96d42a7d6c86b8845c6d914ec47858518ae8c17e3bb  tunnel/amd64/tunnel.dll
8139273351b8609061956029216c339c9ad7305e90c394c9933db8d15afc3ddb  tunnel/arm64/tunnel.dll
2769c99338d4ae5300d0b66c34653e5e669e81acf7bc7b3edf00b555fd9588d7  tunnel/include/tunnel.h
```

### Linux cross-build (amd64) — reproducible

Upstream's `build.bat` is just MinGW + cgo, so it cross-compiles cleanly
from Linux. On Arch:

```sh
sudo pacman -S --needed go mingw-w64-gcc
git submodule update --init --recursive
cd third_party/wireguard-windows/embeddable-dll-service
mkdir -p amd64
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc \
  CGO_CFLAGS="-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0A00" \
  go build -buildmode=c-shared -ldflags="-w -s" -trimpath \
           -o amd64/tunnel.dll .
cd ../../..
cp third_party/wireguard-windows/embeddable-dll-service/amd64/tunnel.dll \
   windows/lib/tunnel/amd64/
cp third_party/wireguard-windows/embeddable-dll-service/amd64/tunnel.h \
   windows/lib/tunnel/include/
sha256sum windows/lib/tunnel/amd64/tunnel.dll \
         windows/lib/tunnel/include/tunnel.h     # update table above
```

The `-trimpath` + `-ldflags="-w -s"` flags + pinned submodule sha + same Go
minor version yield byte-identical output across rebuilds.

### Linux cross-build (arm64)

Arch's `extra` repo doesn't ship `aarch64-w64-mingw32-gcc`, so we use the
LLVM/Clang-based mingw toolchain from AUR (`llvm-mingw`). It ships under
`/opt/llvm-mingw/llvm-mingw-msvcrt/bin/` and produces real MSVCRT-flavoured
Windows-on-ARM PE binaries.

```sh
yay -S llvm-mingw-w64-toolchain-msvcrt-bin
export PATH="/opt/llvm-mingw/llvm-mingw-msvcrt/bin:$PATH"
cd third_party/wireguard-windows/embeddable-dll-service
mkdir -p arm64
GOOS=windows GOARCH=arm64 CGO_ENABLED=1 \
  CC=aarch64-w64-mingw32-clang \
  CGO_CFLAGS="-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0A00" \
  go build -buildmode=c-shared -ldflags="-w -s" -trimpath \
           -o arm64/tunnel.dll .
cd ../../..
cp third_party/wireguard-windows/embeddable-dll-service/arm64/tunnel.dll \
   windows/lib/tunnel/arm64/
sha256sum windows/lib/tunnel/arm64/tunnel.dll  # update table above
```

`tunnel.h` is byte-identical between archs (cgo emits the same prologue),
so a single copy in `tunnel/include/` suffices.

### Bumping the upstream version

```sh
cd third_party/wireguard-windows
git fetch --tags
git checkout v<NEW_TAG>
cd ../..
# rebuild tunnel.dll using the recipe above
git add third_party/wireguard-windows windows/lib/tunnel windows/lib/VERSIONS.md
```

---

## Why both DLLs (short version)

- `wireguard.dll` — userspace shim for the wireguard-nt kernel driver.
  Used to **query stats** (`WireGuardOpenAdapter` + `GetConfiguration`).
- `tunnel.dll` — full wg-quick-equivalent tunnel runtime: parses the
  `.conf`, configures interface IPs / DNS / routes / kill-switch, runs
  inside the Windows service we create per tunnel.

`tunnel.dll` calls into `wireguard.dll` itself; we additionally call
`wireguard.dll` directly for fast stat polling without going through SCM.
