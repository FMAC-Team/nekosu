package me.neko.nksu

import android.app.Application
import kotlin.system.exitProcess
import android.util.Log
import android.os.Process

import me.neko.nksu.ui.util.CrashHandler
import me.neko.nksu.ui.util.NotificationUtil
import me.neko.nksu.util.SigCheck
import me.neko.nksu.R

class NkApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (!SigCheck.validate(this)) {
            Log.w("NkApplication", getString(R.string.sig_check_failed))
            Process.killProcess(Process.myPid())
            exitProcess(1)
        }
        NotificationUtil.createChannel(this)
        CrashHandler.init(this)
    }
}