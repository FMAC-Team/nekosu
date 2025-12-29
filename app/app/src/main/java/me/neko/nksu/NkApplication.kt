package me.neko.nksu

import android.app.Application
import kotlin.system.exitProcess
import android.util.Log
import android.os.Process

import me.neko.nksu.ui.util.CrashHandler
import me.neko.nksu.ui.util.NotificationUtil
import me.neko.nksu.util.SigCheck

class NkApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (!SigCheck.validate(this)) {
            Log.w("NkApplication", "应用签名校验失败，可能是非官方版本。正在终止运行。")
            Process.killProcess(Process.myPid())
            exitProcess(1)
        }
        NotificationUtil.createChannel(this)
        CrashHandler.init(this)
    }
}