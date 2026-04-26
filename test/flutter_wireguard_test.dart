// Dart unit tests for the public flutter_wireguard API.
//
// We mock the Pigeon HostApi by intercepting the BasicMessageChannel that
// Pigeon generates under `dev.flutter.pigeon.flutter_wireguard.*` and replying
// with canned payloads.
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wireguard/flutter_wireguard.dart' as wg;
import 'package:flutter_wireguard/src/messages.g.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  const codec = WireguardHostApi.pigeonChannelCodec;

  void mockHost(String method, Object? Function(List<Object?> args) handler) {
    final channel = 'dev.flutter.pigeon.flutter_wireguard.WireguardHostApi.$method';
    messenger.setMockDecodedMessageHandler<Object?>(
      BasicMessageChannel<Object?>(channel, codec),
      (Object? message) async {
        final args = (message as List<Object?>?) ?? const <Object?>[];
        try {
          return <Object?>[handler(args)];
        } catch (e) {
          return <Object?>['ERR', '$e', null];
        }
      },
    );
  }

  void clearHost(String method) {
    final channel = 'dev.flutter.pigeon.flutter_wireguard.WireguardHostApi.$method';
    messenger.setMockDecodedMessageHandler<Object?>(
      BasicMessageChannel<Object?>(channel, codec), null);
  }

  tearDown(() {
    for (final m in ['start', 'stop', 'status', 'tunnelNames', 'backend']) {
      clearHost(m);
    }
  });

  group('host API', () {
    test('start forwards name + config', () async {
      String? gotName, gotConfig;
      mockHost('start', (args) {
        gotName = args[0] as String;
        gotConfig = args[1] as String;
        return null;
      });
      await wg.start('wg0', '[Interface]\n');
      expect(gotName, 'wg0');
      expect(gotConfig, '[Interface]\n');
    });

    test('stop forwards name', () async {
      String? gotName;
      mockHost('stop', (args) { gotName = args[0] as String; return null; });
      await wg.stop('wg0');
      expect(gotName, 'wg0');
    });

    test('status decodes TunnelStatus', () async {
      mockHost('status', (args) {
        return TunnelStatus(
          name: args[0] as String,
          state: TunnelState.up,
          rx: 100, tx: 200, handshake: 1700000000000,
        );
      });
      final s = await wg.status('wg0');
      expect(s.name, 'wg0');
      expect(s.state, TunnelState.up);
      expect(s.rx, 100);
      expect(s.tx, 200);
      expect(s.handshake, 1700000000000);
    });

    test('tunnelNames returns list', () async {
      mockHost('tunnelNames', (_) => ['wg0', 'home']);
      final names = await wg.tunnelNames();
      expect(names, ['wg0', 'home']);
    });

    test('backend decodes BackendInfo', () async {
      mockHost('backend',
          (_) => BackendInfo(kind: BackendKind.kernel, detail: 'wg-quick (kernel)'));
      final b = await wg.backend();
      expect(b.kind, BackendKind.kernel);
      expect(b.detail, 'wg-quick (kernel)');
    });

    test('platform errors propagate', () async {
      messenger.setMockDecodedMessageHandler<Object?>(
        const BasicMessageChannel<Object?>(
            'dev.flutter.pigeon.flutter_wireguard.WireguardHostApi.start', codec),
        (Object? _) async => <Object?>['START_FAILED', 'boom', null],
      );
      await expectLater(
        wg.start('wg0', ''),
        throwsA(isA<PlatformException>()
            .having((e) => e.code, 'code', 'START_FAILED')
            .having((e) => e.message, 'message', 'boom')),
      );
    });
  });

  group('status stream', () {
    test('events delivered via FlutterApi reach the stream', () async {
      // First subscribe so the FlutterApi is registered.
      final stream = wg.statusStream();
      final received = <wg.TunnelStatus>[];
      final sub = stream.listen(received.add);

      // Synthesise an event by encoding a Pigeon message and sending it on
      // the FlutterApi channel.
      const channel = 'dev.flutter.pigeon.flutter_wireguard.WireguardFlutterApi.onTunnelStatus';
      const flutterCodec = WireguardFlutterApi.pigeonChannelCodec;
      final payload = flutterCodec.encodeMessage(<Object?>[
        TunnelStatus(
          name: 'wg0', state: TunnelState.up, rx: 1, tx: 2, handshake: 3),
      ]);
      await messenger.handlePlatformMessage(channel, payload, (_) {});

      // Allow the broadcast tick to fire.
      await Future<void>.delayed(Duration.zero);
      expect(received, hasLength(1));
      expect(received.single.name, 'wg0');
      expect(received.single.state, TunnelState.up);
      await sub.cancel();
    });
  });
}
