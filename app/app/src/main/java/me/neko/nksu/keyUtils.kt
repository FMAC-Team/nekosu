package me.neko.nksu

import android.content.Context
import android.util.Log
import java.io.File
import java.nio.ByteBuffer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import android.util.Base64
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

object KeyUtils {
    private const val KEY_FILE_NAME = "ecc_private.pem"

    fun checkKeyExists(context: Context): Boolean {
        return File(context.filesDir, KEY_FILE_NAME).exists()
    }

    fun getKeyFilePath(context: Context): String {
        return File(context.filesDir, KEY_FILE_NAME).absolutePath
    }

    fun saveKey(context: Context, key: String) {
        val MAX_SIZE = 4 * 1024
        try {
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            if (keyBytes.size > MAX_SIZE) return
            File(context.filesDir, KEY_FILE_NAME).writeBytes(keyBytes)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getTotpToken(secretBase32: String, timeInterval: Long = 30L): String {
        try {
            val secretBytes = decodeBase32(secretBase32)
            
       
            val time = System.currentTimeMillis() / 1000 / timeInterval
            val data = ByteBuffer.allocate(8).putLong(time).array()

           
            val algo = "HmacSHA1"
            val mac = Mac.getInstance(algo)
            val keySpec = SecretKeySpec(secretBytes, algo)
            mac.init(keySpec)
            val hash = mac.doFinal(data)

            // 4. 动态截断
            val offset = (hash[hash.size - 1] and 0xf.toByte()).toInt()
            var binary = ((hash[offset] and 0x7f.toByte()).toInt() shl 24) or
                    ((hash[offset + 1] and 0xff.toByte()).toInt() shl 16) or
                    ((hash[offset + 2] and 0xff.toByte()).toInt() shl 8) or
                    (hash[offset + 3] and 0xff.toByte()).toInt()

            val otp = binary % 1_000_000
            return String.format("%06d", otp)
        } catch (e: Exception) {
            Log.e("KeyUtils", "TOTP Generation failed: ${e.message}")
            return ""
        }
    }

    private fun decodeBase32(base32: String): ByteArray {
        val base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val cleanInput = base32.trim().replace(" ", "").replace("-", "").uppercase(Locale.ROOT)
        val noPadding = cleanInput.trimEnd('=')
        
        val bytes = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0

        for (char in noPadding) {
            val value = base32Chars.indexOf(char)
            if (value < 0) throw IllegalArgumentException("Invalid Base32 character: $char")

            buffer = (buffer shl 5) or value
            bitsLeft += 5

            if (bitsLeft >= 8) {
                bitsLeft -= 8
                bytes.add((buffer shr bitsLeft).toByte())
            }
        }
        return bytes.toByteArray()
    }
    
    fun isValidECCKey(keyString: String): Boolean {
        if (keyString.isBlank()) return false

        val cleanKey = keyString
            .replace("-----BEGIN (.*)-----".toRegex(), "")
            .replace("-----END (.*)-----".toRegex(), "")
            .replace("\\s".toRegex(), "")

        return try {
            val keyBytes = Base64.decode(cleanKey, Base64.DEFAULT)
            val factory = KeyFactory.getInstance("EC")
            try {
                factory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
                true
            } catch (e: Exception) {
         Log.e("KeyUtils", "No valid private key!")
         false
            }
        } catch (e: Exception) {
            false
        }
    }
}
