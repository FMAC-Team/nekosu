package me.neko.nksu

class Native {
    companion object {
        init {
            System.loadLibrary("nksu")
        }
    }

    external fun authenticate(key: String?, token: String?): Int

    external fun stringFromJNI(): String
}
