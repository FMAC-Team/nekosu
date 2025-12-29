package me.neko.nksu.ui.util

import android.content.Intent
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.net.toUri
import me.neko.nksu.BuildConfig
import me.neko.nksu.ui.util.UpdateChecker

/**
 * 负责检查应用更新并显示更新对话框。
 *
 * @param owner GitHub 仓库所有者。
 * @param repo GitHub 仓库名称。
 */
@Composable
fun CheckUpdate(owner: String, repo: String) {
    val context = LocalContext.current
    var showUpdateDialog by remember { mutableStateOf(false) }
    var latestTag by remember { mutableStateOf<String?>(null) }

    // --- 版本比较逻辑 ---

    /** 从版本字符串中去除前缀和连字符后的内容，仅保留数字部分。 */
    fun stripSuffix(version: String): String =
        version.trimStart('v', 'V').substringBefore('-')

    /** 将版本字符串解析为三位整数列表 (Major, Minor, Patch)。 */
    fun parseNumbers(version: String): List<Int> =
        stripSuffix(version)
            .split('.')
            .map { it.toIntOrNull() ?: 0 }
            .let {
                when {
                    it.size >= 3 -> it.take(3)
                    it.size == 2 -> it + listOf(0)
                    it.size == 1 -> it + listOf(0, 0)
                    else -> listOf(0, 0, 0)
                }
            }

    /** 比较远程版本是否大于本地版本。 */
    fun isRemoteGreater(local: String, remote: String): Boolean {
        val localNums = parseNumbers(local)
        val remoteNums = parseNumbers(remote)
        for (i in 0..2) {
            if (remoteNums[i] > localNums[i]) return true
            if (remoteNums[i] < localNums[i]) return false
        }
        return false
    }

    // --- 更新检查副作用 ---

    LaunchedEffect(Unit) {
        UpdateChecker.fetchLatestVersion(owner, repo)?.let { remoteVer ->
            latestTag = remoteVer
            if (isRemoteGreater(BuildConfig.VERSION_NAME, remoteVer)) {
                showUpdateDialog = true
            }
        }
    }

    // --- 更新对话框 UI ---

    if (showUpdateDialog && latestTag != null) {
        AlertDialog(
            onDismissRequest = { showUpdateDialog = false },
            title = { Text("检测到新版本") },
            text = {
                Text(
                    "当前版本：${BuildConfig.VERSION_NAME}\n" +
                            "最新版本：$latestTag\n\n" +
                            "针对你的牛牛进行了一些优化，是否前往 GitHub 下载？"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showUpdateDialog = false
                    val intent = Intent(
                        Intent.ACTION_VIEW,
                        "https://github.com/$owner/$repo/releases/latest".toUri()
                    )
                    context.startActivity(intent)
                }) { Text("去下载") }
            },
            dismissButton = {
                TextButton(onClick = { showUpdateDialog = false }) {
                    Text("稍后再说")
                }
            }
        )
    }
}
