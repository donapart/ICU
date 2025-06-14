# Architecture Overview

The application uses a multi factor authentication flow combining biometrics, a user PIN and a NFC tag. The master key for the local password database is stored encrypted on the NFC tag. When the user launches the app the following steps occur:

1. **Biometric check** using the device API. A failure falls back to PIN entry.
2. **NFC tag** is scanned. The encrypted master key together with a random salt and IV is read from the tag.
3. The **master key** is decrypted using PBKDF2 derived from the PIN. AES‑GCM ensures confidentiality and integrity.
4. The **SQLCipher** database is opened with this key and the password vault becomes available.

The project is split into several modules:

- `auth_core/` – shared logic for biometrics, PIN handling and session orchestration
- `ui_app/` – the Flutter application providing the user interface
- `platform_plugins/` – native plugins for NFC and secure key operations

Each encrypted payload stored on the tag contains its own 16‑byte salt and
12‑byte IV so the key derivation and decryption steps are fully
self‑contained. The integrity tag produced by AES‑GCM is appended to the
ciphertext and verified during decryption.
