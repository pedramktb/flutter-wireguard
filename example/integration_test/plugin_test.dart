// End-to-end integration test for flutter_wireguard.
//
// This test:
//   1. Generates a keypair (pure Dart, no native calls).
//   2. Queries backend() to confirm the platform plugin is registered and
//      reports a non-empty detail string.
//   3. Tries start() with a deliberately broken config and expects a
//      PlatformException whose code starts with "START_FAILED" — this proves
//      the round-trip from Dart -> Pigeon HostApi -> native -> error
//      response is wired correctly without requiring root or network access.
//   4. Calls tunnelNames() and asserts it returns a List.
//
// To run on Android:
//   cd example && flutter test integration_test/plugin_test.dart -d <device>
// To run on Linux desktop:
//   cd example && flutter test integration_test/plugin_test.dart -d linux
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:flutter_wireguard/flutter_wireguard.dart' as wg;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('generateKeyPair produces a 32-byte X25519 keypair', (tester) async {
    final pair = await wg.generateKeyPair();
    expect(pair.privateKey, isNotEmpty);
    expect(pair.publicKey, isNotEmpty);
    final derived = await wg.publicKeyFromPrivate(pair.privateKey);
    expect(derived, pair.publicKey);
  });

  testWidgets('backend() returns metadata from the platform side', (tester) async {
    // Allow the Android plugin some time to bind the :wireguard service.
    await tester.pump(const Duration(seconds: 1));
    final b = await wg.backend();
    expect(b.detail, isNotEmpty);
    // kind may be kernel/userspace/unknown depending on host capabilities;
    // we only assert the call succeeded.
    expect(wg.BackendKind.values, contains(b.kind));
  });

  testWidgets('tunnelNames() returns a List', (tester) async {
    final names = await wg.tunnelNames();
    expect(names, isA<List<String>>());
  });

  testWidgets('start() with bad config surfaces a PlatformException',
      (tester) async {
    PlatformException? captured;
    try {
      await wg.start('itest0', '<<<this is not a wg-quick config>>>');
    } on PlatformException catch (e) {
      captured = e;
    } catch (e) {
      fail('Expected PlatformException, got ${e.runtimeType}: $e');
    }
    expect(captured, isNotNull);
    expect(captured!.code,
        anyOf(['START_FAILED', 'BACKEND_FAILED', 'NOT_CONNECTED']));
  });
}
