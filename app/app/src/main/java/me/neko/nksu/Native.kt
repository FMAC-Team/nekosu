package me.neko.nksu

import android.content.Context

class Native {
    companion object {
        init {
            System.loadLibrary("nksu")
        }
    }

    external fun authenticate(key: String?, token: String?): Int
    external fun Sigcheck(context: Context): Boolean
}
