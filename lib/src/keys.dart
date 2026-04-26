/// Pure-Dart WireGuard key generation helpers.
///
/// WireGuard uses Curve25519 (X25519). Keys are 32 bytes each, exchanged in
/// base64. This module produces / parses keys that are byte-for-byte
/// compatible with `wg genkey`, `wg pubkey`, and `wg genpsk`.
library flutter_wireguard.keys;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A WireGuard keypair: 32-byte X25519 private/public keys, base64 encoded.
class WireGuardKeyPair {
  const WireGuardKeyPair({required this.privateKey, required this.publicKey});

  /// 32-byte private key, base64 encoded (matches `wg genkey`).
  final String privateKey;

  /// 32-byte public key, base64 encoded (matches `wg pubkey`).
  final String publicKey;

  @override
  String toString() => 'WireGuardKeyPair(public=$publicKey)';
}

/// Generate a fresh X25519 keypair suitable for a WireGuard interface or peer.
Future<WireGuardKeyPair> generateKeyPair() async {
  final algorithm = Cryptography.instance.x25519();
  final pair = await algorithm.newKeyPair();
  final priv = await pair.extractPrivateKeyBytes();
  final pub = (await pair.extractPublicKey()).bytes;
  return WireGuardKeyPair(
    privateKey: base64Encode(priv),
    publicKey: base64Encode(pub),
  );
}

/// Derive a public key from an existing base64-encoded WireGuard private key.
///
/// Throws [FormatException] if [privateKeyBase64] is not a valid 32-byte
/// base64 string.
Future<String> publicKeyFromPrivate(String privateKeyBase64) async {
  final bytes = base64Decode(privateKeyBase64);
  if (bytes.length != 32) {
    throw const FormatException('WireGuard private key must be 32 bytes');
  }
  final algorithm = Cryptography.instance.x25519();
  final pair = await algorithm.newKeyPairFromSeed(bytes);
  final pub = (await pair.extractPublicKey()).bytes;
  return base64Encode(pub);
}

/// Generate a fresh 32-byte preshared key (matches `wg genpsk`).
String generatePresharedKey() {
  final secretBox = SecretKeyData.random(length: 32);
  // ignore: invalid_use_of_protected_member
  final bytes = secretBox.bytes;
  return base64Encode(Uint8List.fromList(bytes));
}
