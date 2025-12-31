package me.neko.nksu

import android.content.Context
import java.io.File

object KeyUtils {
    private const val KEY_FILE_NAME = "ecc_private.pem"
    fun checkKeyExists(context: Context): Boolean {
        val file = File(context.filesDir, KEY_FILE_NAME)
        return file.exists()
    }
    
fun saveKey(context: Context, key: String) {
    val MAX_SIZE = 512 * 1024 // 512KB

    try {
        val keyBytes = key.toByteArray(Charsets.UTF_8)

        if (keyBytes.size > MAX_SIZE) {
            Log.e("StorageError", "数据过大 (${keyBytes.size} bytes)，拒绝写入")
            return 
        }
        File(context.filesDir, KEY_FILE_NAME).writeBytes(keyBytes)

    } catch (e: Exception) {
        e.printStackTrace()
    }
}


}
