# flutter_wireguard

A Flutter plugin for creating and managing [WireGuard](https://www.wireguard.com/) VPN tunnels.

## Platform support

| Android | Linux | iOS | macOS | Windows |
|:---:|:---:|:---:|:---:|:---:|
| ✅ | ✅ | 🚧 | 🚧 | 🚧 |

The API is identical across supported platforms (multi-tunnel, status streaming, backend introspection, key generation).

## Install

```yaml
dependencies:
  flutter_wireguard: ^0.1.0
```

## Usage

The API is a small set of top-level functions — no facade class to instantiate.

```dart
import 'package:flutter_wireguard/flutter_wireguard.dart' as wg;
```

### Start / stop a tunnel

```dart
await wg.start(
  name: 'wg0',
  config: '''
[Interface]
PrivateKey = <your-private-key>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
''',
);

await wg.stop(name: 'wg0');
```

### Query / stream tunnel status

```dart
final TunnelStatus s = await wg.status(name: 'wg0');
print('${s.name} ${s.state} rx=${s.rx} tx=${s.tx} hs=${s.handshake}');

wg.statusStream().listen((TunnelStatus s) {
  print('${s.name}: ${s.state}'); // TunnelState.up | down | toggle
});
```

### List active tunnels

```dart
final List<String> names = await wg.tunnelNames();
```

### Backend introspection

```dart
final BackendInfo b = await wg.backend();
// b.kind: BackendKind.kernel | userspace | unknown
// b.detail: e.g. "WgQuickBackend (kernel)" / "wg-quick + wireguard-go"
```

### Key generation (pure Dart, no native call)

```dart
final kp = await wg.generateKeyPair();         // base64 X25519
final pub = await wg.publicKeyFromPrivate(kp.privateKey);
final psk = wg.generatePresharedKey();
```

## Platform notes

### Android (minSdk 26)

The WireGuard Go runtime runs in a dedicated `:wireguard` process (isolated from the main Flutter process) so the JVM never holds two Go runtimes at once. VPN permission is requested automatically when the plugin attaches to an activity.

Required manifest entry:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

`BIND_VPN_SERVICE` is contributed by the WireGuard library.

### Linux

Linux uses the system `wg-quick` tool, automatically falling back to a userspace implementation when the in-kernel module is unavailable.

Required:

- `wireguard-tools` (provides `wg`, `wg-quick`)
- A `resolvconf` provider — either `openresolv` or `systemd-resolved` — **only if your config sets `DNS = ...`**. `wg-quick` calls `resolvconf` to install/restore DNS servers and will fail at start if neither is present. Configs without a `DNS =` line work fine without it.
- One of the following for kernel-less systems: `wireguard-go`, `boringtun-cli`, or `boringtun`
- `polkit` (provides `pkexec`) when the calling user is not root

The plugin runs `wg-quick` directly when it is root; otherwise it elevates via `pkexec`. The pkexec child is **persistent** — one prompt at the first privileged op covers every subsequent Start / Stop / Status for the lifetime of the app. Status polls also avoid prompting by reading byte counters from `/sys/class/net/<iface>/statistics/{rx,tx}_bytes` (world-readable). Tunnel configurations are written to `$XDG_RUNTIME_DIR/flutter_wireguard/<name>.conf` with `0600` permissions; tunnel names are validated (max 15 chars, `[A-Za-z0-9_=+.-]`) before reaching the shell.

#### Packaging for Linux distributions

The plugin discovers `wg-quick`, `wg`, `pkexec`, and the userspace impl (`wireguard-go` / `boringtun-cli` / `boringtun`) on `$PATH` at runtime. Bundling is therefore a packaging-layer concern, not a plugin-layer one. Recipes for the common formats:

- **Debian / Ubuntu (`.deb`)** — `Depends: wireguard-tools, policykit-1` in `debian/control`; `wireguard-tools` already `Recommends: openresolv | systemd-resolved` so DNS works out of the box. Add `Recommends: wireguard-go` for users on kernels without the in-tree module.
- **Fedora / RHEL (`.rpm`)** — `Requires: wireguard-tools, polkit` in your spec; add `Requires: systemd-resolved` (or `openresolv` from EPEL) if your tunnels use `DNS =`. Optional: `Recommends: wireguard-tools` and `wireguard-go` from RPM Fusion.
- **Arch (`PKGBUILD`)** — `depends=('wireguard-tools' 'polkit')`, `optdepends=('openresolv: DNS handling for wg-quick `DNS =`' 'wireguard-go: userspace impl for kernels without the module')`.
- **Snap** — add `wireguard-tools` to `stage-packages` and the `network-control` interface plug. Build `wireguard-go` from source as a separate `parts` entry if needed.
- **AppImage** — bundle `wireguard-tools` and `wireguard-go` inside the AppDir; prepend `$APPDIR/usr/bin` to `PATH` before launch. The host still needs polkit.
- **Flatpak** — build `wireguard-tools` and (optionally) `wireguard-go` as `modules` in your manifest. Note that `pkexec` does not work from inside the sandbox; either ship a system D-Bus helper, talk to polkit directly, or set `FLUTTER_WIREGUARD_ELEVATE=flatpak-spawn --host pkexec` to escape the sandbox for elevation. Permissions: `--share=network`, `--device=all` (for `/dev/net/tun`), `--filesystem=xdg-run/flutter_wireguard:create`.

##### Customising privilege elevation

The environment variable `FLUTTER_WIREGUARD_ELEVATE` lets the embedding app override how the plugin acquires `CAP_NET_ADMIN`:

| Value | Behavior |
|---|---|
| _unset_ or empty | Default: spawn `pkexec sh -c <loop>` (one prompt per app session). |
| `none` | Skip elevation entirely. The plugin runs `wg-quick`/`wg` directly. Use when the app already has `CAP_NET_ADMIN` (e.g. a system service started by systemd with `AmbientCapabilities=CAP_NET_ADMIN`). |
| any other string | Whitespace-split argv prefix that wraps the persistent shell — e.g. `flatpak-spawn --host pkexec` to escape a flatpak sandbox, or `sudo -A` for a custom askpass helper. |

### iOS / macOS / Windows

> ⚠️ Not yet implemented.

## Example

A full-featured example app lives under [example/](example/) — keypair generation, saved tunnels, live status, backend banner. Run it with:

```bash
cd example
flutter run -d linux    # or: -d <android-device-id>
```

## Testing

```bash
# Dart unit tests
flutter test

# Android Kotlin (Robolectric) tests
cd example/android && ./gradlew :flutter_wireguard:testDebugUnitTest

# Linux native (gtest) tests
cmake -S linux -B linux/build -Dinclude_flutter_wireguard_tests=ON
cmake --build linux/build && ctest --test-dir linux/build --output-on-failure

# Integration tests (require a device / desktop)
cd example && flutter test integration_test
```

## License

See [LICENSE](LICENSE).
