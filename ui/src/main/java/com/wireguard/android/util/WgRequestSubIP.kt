import android.util.Log
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import android.os.Handler
import android.os.Looper

object WgRequestSubIP {
    private const val TAG = "WireGuard"

    interface RequestCallback {
        fun onSuccess(allowedIP: String)
        fun onError(error: String)
    }

    fun requestSubIP(ip: String, publicKey: String, uuid: String, callback: RequestCallback) {
        Thread {
            var connection: HttpURLConnection? = null
            try {
                val url = URL("http://$ip:1444/add_peer")
                connection = url.openConnection() as HttpURLConnection

                connection.apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 4000
                    readTimeout = 4000
                    doOutput = true
                }

                val jsonBody = JSONObject().apply {
                    put("public_key", publicKey)
                    put("uuid", uuid)
                }
                val jsonString = jsonBody.toString()

                Log.d(TAG, "正在请求: $url")
                Log.d(TAG, "请求参数: $jsonString")

                connection.outputStream.use { os ->
                    os.write(jsonString.toByteArray(StandardCharsets.UTF_8))
                }

                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    Log.e(TAG, "请求失败: ${connection.responseCode}")
                    Handler(Looper.getMainLooper()).post {
                        callback.onError("HTTP 请求失败: ${connection.responseCode}")
                    }
                    return@Thread
                }

                val response = connection.inputStream.bufferedReader().use { it.readText() }
                val jsonResponse = JSONObject(response)
                val allowedIP = jsonResponse.getString("allowed_ip")

                Log.d(TAG, "获取到子网 IP: $allowedIP")

                Handler(Looper.getMainLooper()).post {
                    callback.onSuccess(allowedIP)
                }

            } catch (e: Exception) {
                Log.e(TAG, "请求出错: ${e.message}")
                Handler(Looper.getMainLooper()).post {
                    callback.onError(e.message ?: "未知错误")
                }
            } finally {
                connection?.disconnect()
            }
        }.start()
    }
}