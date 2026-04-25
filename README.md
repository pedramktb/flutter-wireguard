# flutter_wireguard

A Flutter plugin for creating and managing [WireGuard](https://www.wireguard.com/) VPN tunnels on Android, iOS, macOS, Linux, and Windows.

## Platform support

| Android | iOS | macOS | Linux | Windows |
|:---:|:---:|:---:|:---:|:---:|
| ✅ | 🚧 | 🚧 | 🚧 | 🚧 |

## Usage

```dart
import 'package:flutter_wireguard/flutter_wireguard.dart';

final wireguard = FlutterWireguard();
```

### Start a tunnel

```dart
await wireguard.start(
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
```

### Stop a tunnel

```dart
await wireguard.stop(name: 'wg0');
```

### Query tunnel status

```dart
final status = await wireguard.status(name: 'wg0');
// status keys: name, state, rx (bytes), tx (bytes), handshake (epoch ms)
print(status['state']); // e.g. "CONNECTED"
```

### Listen to live status updates

```dart
wireguard.statusStream().listen((status) {
  print('${status['name']}: ${status['state']}');
});
```

### Query the active backend (Android)

```dart
final backend = await wireguard.backendType();
// "GoBackend" or "WgQuickBackend (kernel)"
```

## Android notes

On Android the WireGuard Go runtime runs in a dedicated `:wireguard` process (isolated from the main Flutter process) to prevent dual-Go-runtime crashes. VPN permission is requested automatically when the plugin attaches to an activity.

## Permissions

### Android

Add the following to your app's `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

The `BIND_VPN_SERVICE` permission is declared by the WireGuard library automatically.

### iOS / macOS

> ⚠️ Not yet implemented.

