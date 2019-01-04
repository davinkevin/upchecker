package com.github.davinkevin

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.net.ssl.*


fun main(args: Array<String>) {

    if (args.size != 1 ) {
        println("Error !")
        return
    }

    disableHttpsCheck()

    val url = URL(args[0])
    println("I will try to access $url")


    var results = mutableListOf<CheckMessage>()
    onClose { results }
    while (true) {
        TimeUnit.SECONDS.sleep(1)
        val c = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 1000
            readTimeout= 1000
            instanceFollowRedirects = true
        }

        results.add(c.toCheckMessage())
    }
}

fun disableHttpsCheck() {
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkServerTrusted(p0: Array<out java.security.cert.X509Certificate>?, p1: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> { return arrayOf() }
        override fun checkClientTrusted(p0: Array<out java.security.cert.X509Certificate>?, p1: String?) {}
    })

    val allHostsValid = HostnameVerifier { _, _ -> true }

    val sc = SSLContext.getInstance("TLS")
    sc.init(null, trustAllCerts, java.security.SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.socketFactory)
    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid)
}

fun onClose(v: () -> List<CheckMessage>) {
    Runtime.getRuntime().addShutdownHook(object : Thread() {
        override fun run() {
            v()
                .groupBy { it.code }
                .mapValues { it.value.size }
                .forEach {
                    println("""There was ${it.value} message ${it.key}""")
                }
        }
    })
}

enum class Status { OK, STRANGE, ERROR }
data class CheckMessage(val status: Status, val code: Int)
fun HttpURLConnection.toCheckMessage(): CheckMessage {
    val rCode = this.responseCode

    val message = if (rCode in 200..299) {
        println("All is ok 👍")
        CheckMessage(Status.OK, rCode)
    } else if (rCode in 500..599) {
        println("\uD83D\uDD25 Error $rCode")
        CheckMessage(Status.ERROR, rCode)
    } else {
        println("Error in others range 🤔")
        CheckMessage(Status.STRANGE, rCode)
    }

    this.disconnect()

    return message
}