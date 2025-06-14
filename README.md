# NFC Password Manager

This repository provides a starting point for a cross-platform password manager that combines multiple authentication factors:

- Biometrics (e.g. fingerprint, FaceID)
- PIN-based fallback
- A NFC tag that stores an encrypted master key

All user data is encrypted locally using SQLCipher. The master key is derived
from the user's PIN with PBKDF2 and can be stored on an NFC tag. Each payload on
the tag bundles its own salt and IV so the key can always be recovered offline.
The PIN itself is never written to disk.

The project is organized into separate modules for easier maintenance.

See the `docs/` directory for further details about the architecture.
