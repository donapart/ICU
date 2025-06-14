import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:local_auth/local_auth.dart';
import 'package:nfc_manager/nfc_manager.dart';

/// Core authentication utilities handling biometrics and NFC key retrieval.
class AuthCore {
  final LocalAuthentication _auth = LocalAuthentication();

  /// Performs a biometric check. Returns true if the user successfully
  /// authenticated using fingerprint or face recognition.
  Future<bool> authenticateBiometrics() async {
    return _auth.authenticate(
      localizedReason: 'Authenticate to access your vault',
      options: const AuthenticationOptions(biometricOnly: true),
    );
  }

  /// Reads the encrypted master key from an NFC tag and decrypts it using the
  /// provided [pin]. The payload stored on the tag must contain the salt (16 B),
  /// the AES-GCM IV (12 B) and the ciphertext including MAC.
  Future<Uint8List?> readMasterKey(String pin) async {
    Uint8List? encrypted;
    Uint8List? salt;
    Uint8List? iv;

    await NfcManager.instance.startSession(onDiscovered: (tag) async {
      final ndef = Ndef.from(tag);
      if (ndef != null) {
        final payload = ndef.cachedMessage?.records.first.payload;
        if (payload != null && payload.length >= 28) {
          salt = Uint8List.sublistView(payload, 0, 16);
          iv = Uint8List.sublistView(payload, 16, 28);
          encrypted = Uint8List.sublistView(payload, 28);
        }
      }
      NfcManager.instance.stopSession();
    });

    if (encrypted == null || salt == null || iv == null) {
      return null;
    }

    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    final secretKey = await pbkdf2.deriveKey(
      secretKey: SecretKey(pin.codeUnits),
      nonce: salt!,
    );

    final cipher = AesGcm.with256bits();
    final box = SecretBox(encrypted!, nonce: iv!, mac: Mac.empty);
    final key = await cipher.decrypt(box, secretKey: secretKey);
    return Uint8List.fromList(key);
  }

  /// Encrypts [masterKey] with a key derived from [pin] and writes it to the
  /// supplied NFC [tag]. Salt and IV are generated randomly and stored together
  /// with the ciphertext on the tag.
  Future<void> writeMasterKey(Tag tag, Uint8List masterKey, String pin) async {
    final random = Random.secure();
    final salt =
        Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));

    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    final secretKey = await pbkdf2.deriveKey(
      secretKey: SecretKey(pin.codeUnits),
      nonce: salt,
    );

    final cipher = AesGcm.with256bits();
    final box = await cipher.encrypt(masterKey, secretKey: secretKey);
    final payload = Uint8List.fromList(salt + box.nonce + box.cipherText);

    final ndef = Ndef.from(tag);
    if (ndef == null) {
      throw Exception('NDEF not supported');
    }
    await ndef.write(NdefMessage([
      NdefRecord.mime('application/vnd.myapp.masterkey', payload),
    ]));
  }
}
