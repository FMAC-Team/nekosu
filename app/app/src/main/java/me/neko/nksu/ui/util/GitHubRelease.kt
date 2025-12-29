package me.neko.nksu.ui.util

import android.util.Log
import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

data class GitHubRelease(
    @param:Json(name = "tag_name") val tagName: String,
    @param:Json(name = "name") val releaseName: String
)

object UpdateChecker {
    private val client = OkHttpClient()
    private val moshi = Moshi.Builder()
        .add(com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory())
        .build()
    private val adapter = moshi.adapter(GitHubRelease::class.java)

    suspend fun fetchLatestVersion(owner: String, repo: String): String? =
        withContext(Dispatchers.IO) {
            try {
                val resp = client.newCall(
                    Request.Builder()
                        .url("https://api.github.com/repos/$owner/$repo/releases/latest")
                        .header("User-Agent", "MyApp/1.0") // 避免 403
                        .build()
                ).execute()

                if (!resp.isSuccessful) return@withContext null

                val body = resp.body.string().also {
                    Log.d("UpdateCheck", "GitHub raw JSON: $it")
                }

                adapter.fromJson(body)?.releaseName
            } catch (e: Exception) {
                Log.e("UpdateCheck", "Error checking update", e)
                null
            }
        }
}
