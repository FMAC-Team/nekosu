package me.neko.nksu.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

suspend fun fetchSELinuxStatus(): String = withContext(Dispatchers.IO) {
    try {
        val output = ShellUtils.runSh("getenforce").trim()

        when {
            output.equals("Enforcing", ignoreCase = true) -> "Enforcing"
            output.equals("Permissive", ignoreCase = true) -> "Permissive"
            output.equals("Disabled", ignoreCase = true) -> "Disabled"
            output.contains("Permission denied", ignoreCase = true) -> "Enforcing"
            output.isBlank() || output.startsWith("Error") -> "获取失败"
            else -> "未知 ($output)"
        }
    } catch (e: Exception) {
        "获取失败: ${e.message}"
    }
}
