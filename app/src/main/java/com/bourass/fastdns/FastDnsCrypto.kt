package com.bourass.fastdns

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object FastDnsCrypto {
    // Extracted Master Key from libfvpnkeys.so NativeKeys.masterKey()
    const val MASTER_KEY_HEX = "3529de18502ac35a534ce8b541d834228ca3c1cd89b6ce3d31cf44072f0e477a"
    const val DEFAULT_SUB_ID = "1122334455667788"
    const val DEFAULT_ZONE = "dns.marocdns.uk"
    const val DEFAULT_TARGET_IP = "37.221.198.37"
    const val APP_CERT_SHA256 = "018f8bcd84ff15310d78e48257278e54c676a2732afe6cf89672a3ca841f6054"
    const val CERT_HEX = "c39a8841ecb915f1ba6462f486ee009219b052db290f5209f53d34c31c56ab41"

    val INITIAL_POOL = listOf(
        "1122334455667788",
        "d6ec7d72c0bdf860",
        "23d5e6fa2198b0bd",
        "bf3e0703a7095d41",
        "4ad9663fa2800dcf",
        "c34f930d89fbd396",
        "5d1793e49ea04d42",
        "2503e1acb9104230",
        "a52257518f759fbe",
        "8c3987d0c84539eb",
        "1db28923c5e6fe6c",
        "551c6a71203d2e7c",
        "2d1f737e8df3f7c8",
        "b15b622070e682a9",
        "b891c44f58a09268",
        "7e640b1f82cf50fb",
        "c9cd858456937ebd",
        "3472b6e3e7914aef",
        "7493d7fab1c1d5b4"
    )

    fun deriveInstallId(subId: String): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val digest = md.digest(("fv-install-bind-v1:$subId").toByteArray(Charsets.UTF_8))
        return bytesToHex(digest).substring(0, 32)
    }

    fun provisionAccount(hwid: String): Boolean {
        return try {
            val ts = (System.currentTimeMillis() / 1000).toString()
            val subKey = deriveSubKey(hwid)
            val msg = "chk1$hwid|$ts".toByteArray(Charsets.UTF_8)
            val sign = bytesToHex(hmacSha256(subKey, msg)).lowercase()
            val installId = deriveInstallId(hwid)

            val url = java.net.URL("https://panel.marocdns.uk/api/app/config-check")
            val conn = url.openConnection() as javax.net.ssl.HttpsURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("X-Hwid", hwid)
            conn.setRequestProperty("X-Ts", ts)
            conn.setRequestProperty("X-Sign", sign)
            conn.setRequestProperty("X-Vpn-Connected", "0")
            conn.setRequestProperty("X-App-Vc", "110")
            conn.setRequestProperty("X-App-Vn", "1.11.0")
            conn.setRequestProperty("X-App-Cert", APP_CERT_SHA256)
            conn.setRequestProperty("X-Install-Id", installId)
            conn.setRequestProperty("User-Agent", "okhttp/4.12.0")

            val code = conn.responseCode
            conn.disconnect()
            code == 200
        } catch (_: Exception) {
            false
        }
    }

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
