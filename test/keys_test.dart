import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wireguard/flutter_wireguard.dart';

void main() {
  group('WireGuard keypair', () {
    test('generateKeyPair produces 32-byte base64 keys', () async {
      final pair = await generateKeyPair();
      expect(base64Decode(pair.privateKey), hasLength(32));
      expect(base64Decode(pair.publicKey), hasLength(32));
    });

    test('publicKeyFromPrivate is deterministic and matches generateKeyPair',
        () async {
      final pair = await generateKeyPair();
      final derived = await publicKeyFromPrivate(pair.privateKey);
      expect(derived, pair.publicKey);
    });

    test('publicKeyFromPrivate rejects malformed keys', () async {
      await expectLater(
        publicKeyFromPrivate('AAAA'),
        throwsA(isA<FormatException>()),
      );
    });

    test('generatePresharedKey produces 32-byte base64 key', () {
      final psk = generatePresharedKey();
      expect(base64Decode(psk), hasLength(32));
    });

    test('two generated keypairs differ', () async {
      final a = await generateKeyPair();
      final b = await generateKeyPair();
      expect(a.privateKey, isNot(b.privateKey));
      expect(a.publicKey, isNot(b.publicKey));
    });
  });
}
