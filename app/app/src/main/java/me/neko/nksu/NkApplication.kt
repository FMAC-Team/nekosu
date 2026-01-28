package me.neko.nksu

import android.app.Application
import android.os.Process
import android.util.Log
import kotlin.system.exitProcess
import me.neko.nksu.R
import me.neko.nksu.ui.util.CrashHandler
import me.neko.nksu.util.SigCheck

class NkApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (!SigCheck.validate(this)) {
            Log.w("NkApplication", getString(R.string.sig_check_failed))
            Process.killProcess(Process.myPid())
            exitProcess(1)
        }
        //      NotificationUtil.createChannel(this)
        CrashHandler.init(this)
    }
}
