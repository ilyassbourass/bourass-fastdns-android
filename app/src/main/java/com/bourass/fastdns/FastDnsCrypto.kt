package com.bourass.fastdns

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object FastDnsCrypto {
    // Extracted Master Key from libfvpnkeys.so NativeKeys.masterKey()
    const val MASTER_KEY_HEX = "3529de18502ac35a534ce8b541d834228ca3c1cd89b6ce3d31cf44072f0e477a"
    const val DEFAULT_SUB_ID = "4db6aa8190671ed0"
    const val DEFAULT_INSTALL_ID = "73f7f016233cf06ab0eeeea89e0ec50c"
    const val CERT_HEX = "c39a8841ecb915f1ba6462f486ee009219b052db290f5209f53d34c31c56ab41"

    fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
        }
        return data
    }

    fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun deriveSubKey(subId: String): ByteArray {
        val masterKey = hexToBytes(MASTER_KEY_HEX)
        return hmacSha256(masterKey, subId.toByteArray(Charsets.UTF_8))
    }

    fun deriveHandshakeKey(subKey: ByteArray, installId: String): ByteArray {
        val msg = "hs1".toByteArray() + byteArrayOf(0x00) +
                installId.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) +
                CERT_HEX.toByteArray(Charsets.UTF_8)
        return hmacSha256(subKey, msg)
    }

    fun deriveSessionKey(subKey: ByteArray, installId: String, sessionId: String): ByteArray {
        val msg = installId.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) +
                sessionId.toByteArray(Charsets.UTF_8) + byteArrayOf(0x00) +
                CERT_HEX.toByteArray(Charsets.UTF_8)
        return hmacSha256(subKey, msg)
    }

    fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv) // 128-bit tag
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(plaintext) // ciphertext + tag appended
    }

    fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(ciphertextAndTag)
    }

    // RFC 4648 Base32 (lowercase, no padding) for DNS label encoding
    private const val BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"

    fun base32Encode(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                val index = (buffer shr bitsLeft) and 0x1F
                sb.append(BASE32_CHARS[index])
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            sb.append(BASE32_CHARS[index])
        }
        return sb.toString()
    }

    fun base32Decode(encoded: String): ByteArray {
        val output = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (c in encoded.lowercase()) {
            val value = BASE32_CHARS.indexOf(c)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                output.add(((buffer shr bitsLeft) and 0xFF).toByte())
            }
        }
        return output.toByteArray()
    }

    /**
     * Split a Base32-encoded string into DNS labels (max 63 chars each).
     */
    fun splitIntoLabels(b32: String, maxLabelLen: Int = 63): List<String> {
        val labels = mutableListOf<String>()
        var i = 0
        while (i < b32.length) {
            val end = minOf(i + maxLabelLen, b32.length)
            labels.add(b32.substring(i, end))
            i = end
        }
        return labels
    }
}
