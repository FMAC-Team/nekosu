package me.neko.nksu.util

object ShellUtils {
    fun runSh(command: String): String = try {
        val process = Runtime.getRuntime().exec(command)
        val output =
            process.inputStream
                .bufferedReader()
                .use { it.readText() }
                .trim()
        val error =
            process.errorStream
                .bufferedReader()
                .use { it.readText() }
                .trim()

        if (process.waitFor() == 0) {
            output
        } else {
            error
        }
    } catch (e: Exception) {
        e.message ?: "Error"
    }
}
