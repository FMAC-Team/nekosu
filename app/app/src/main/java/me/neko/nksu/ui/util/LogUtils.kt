package me.neko.nksu.utils

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileOutputStream

object LogUtils {
    /**
     * 导出并分享日志文件
     */
    fun exportLogs(context: Context) {
        try {
            // 1. 获取 logcat 日志
            val process = Runtime.getRuntime().exec("logcat -d")
            val logText = process.inputStream.bufferedReader().use { it.readText() }

            // 2. 创建临时文件 (保存到应用缓存目录)
            val logFile = File(context.cacheDir, "nekosu_log_${System.currentTimeMillis()}.txt")
            FileOutputStream(logFile).use { fos ->
                fos.write(logText.toByteArray())
            }

            // 3. 弹出分享菜单
            shareLogFile(context, logFile)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(context, "导出日志失败: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun shareLogFile(
        context: Context,
        file: File,
    ) {
        // 注意：你需要在 AndroidManifest 中配置 FileProvider
        val authority = "${context.packageName}.fileprovider"
        val contentUri: Uri = FileProvider.getUriForFile(context, authority, file)

        val intent =
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

        context.startActivity(Intent.createChooser(intent, "分享/导出日志"))
    }
}
