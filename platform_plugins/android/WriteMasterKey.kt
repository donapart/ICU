package com.example.platform_plugins

import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Example helper that encrypts a master key with PBKDF2 + AES/GCM and
 * writes it onto an NFC tag. The payload layout is:
 *   salt(16) | iv(12) | ciphertext
 */
object WriteMasterKey {
    fun write(tag: Tag, masterKey: ByteArray, pin: String) {
        val random = SecureRandom()
        val salt = ByteArray(16).also { random.nextBytes(it) }

        val spec = PBEKeySpec(pin.toCharArray(), salt, 100_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        val aesKey = SecretKeySpec(keyBytes, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(masterKey)

        val payload = salt + iv + encrypted
        val ndef = Ndef.get(tag) ?: throw IllegalArgumentException("NDEF not supported")
        ndef.connect()
        try {
            val record = NdefRecord.createMime("application/vnd.myapp.masterkey", payload)
            val message = NdefMessage(arrayOf(record))
            ndef.writeNdefMessage(message)
        } finally {
            ndef.close()
        }
    }
}
