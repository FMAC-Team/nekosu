package me.neko.nksu

import android.content.Context
import java.io.File

object KeyUtils {
    private const val KEY_FILE_NAME = "ecc_private.pem"
    fun checkKeyExists(context: Context): Boolean {
        val file = File(context.filesDir, KEY_FILE_NAME)
        return file.exists()
    }
}
