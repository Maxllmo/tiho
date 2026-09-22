package app.proxyhub.tv

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import hev.htproxy.TProxyService
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

class ProxyVpnService : VpnService() {
    private val generation = AtomicInteger()
    private var tunFd = -1
    private var bridge: SocksBridge? = null
    @Volatile private var stopping = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        promote()
        Thread({
            if (!startTunnel()) {
                publish(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }, "proxy-start").start()
        return START_STICKY
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun promote() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_MIN)
            channel.setShowBadge(false)
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification = (if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        })
            .setSmallIcon(R.drawable.ic_power)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startTunnel(): Boolean {
        val gen = generation.incrementAndGet()
        val socks = SocksBridge(
            proxyHost = BuildConfig.PROXY_HOST,
            proxyPort = BuildConfig.PROXY_PORT,
            proxyUser = BuildConfig.PROXY_USER,
            proxyPass = BuildConfig.PROXY_PASS,
            protect = { socket -> protect(socket) },
            protectUdp = { socket -> protect(socket) }
        )
        val tun = try {
            socks.start()
            val iface = openTun() ?: return false.also { socks.stop() }
            if (generation.get() != gen) {
                iface.fd.close()
                socks.stop()
                return false
            }
            val cfg = writeConfig(socks.port, iface.ipv6)
            val fd = iface.fd.detachFd()
            tunFd = fd
            bridge = socks
            val started = TProxyService.TProxyStartService(cfg.absolutePath, fd)
            if (!started || generation.get() != gen) {
                stopNative()
                return false
            }
            publish(true)
            true
        } catch (error: Exception) {
            Log.e(TAG, "start failed", error)
            socks.stop()
            closeTun()
            false
        }
        return tun
    }

    private class Tun(val fd: ParcelFileDescriptor, val ipv6: Boolean)

    private fun openTun(): Tun? {
        try {
            val with6 = establish(true)
            if (with6 != null) return Tun(with6, true)
        } catch (error: Exception) {
            Log.w(TAG, "ipv6 tun", error)
        }
        val v4 = establish(false) ?: return null
        return Tun(v4, false)
    }

    private fun establish(ipv6: Boolean): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Proxy")
            .setMtu(1500)
            .addAddress("198.18.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("198.18.0.2")
        if (ipv6) {
            builder.addAddress("fc00::1", 64)
            builder.addRoute("::", 0)
        }
        if (Build.VERSION.SDK_INT >= 29) {
            builder.setMetered(false)
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (error: Exception) {
            Log.w(TAG, "disallow self failed", error)
        }
        return builder.establish()
    }

    private fun writeConfig(port: Int, ipv6: Boolean): File {
        val v6 = if (ipv6) "  ipv6: 'fc00::1'\n" else ""
        val text = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n${v6}  icmp: 'off'\n\n" +
            "socks5:\n  port: $port\n  address: 127.0.0.1\n  udp: 'udp'\n\n" +
            "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n" +
            "  netmask: 255.192.0.0\n  cache-size: 10000\n\n" +
            "misc:\n  connect-timeout: 15000\n  tcp-read-write-timeout: 300000\n  log-level: error\n"
        val file = File(cacheDir, "hev.yml")
        file.writeText(text)
        return file
    }

    private fun stopTunnel() {
        if (stopping) return
        stopping = true
        generation.incrementAndGet()
        publish(false)
        stopNative()
        stopping = false
    }

    private fun stopNative() {
        try {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        } catch (error: Exception) {
            Log.w(TAG, "native stop", error)
        }
        closeTun()
        bridge?.stop()
        bridge = null
    }

    private fun closeTun() {
        val fd = tunFd
        tunFd = -1
        if (fd >= 0) {
            try {
                ParcelFileDescriptor.adoptFd(fd).close()
            } catch (_: Exception) {
            }
        }
    }

    companion object {
        private const val TAG = "ProxyHubTV"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1

        @Volatile
        var isRunning: Boolean = false

        @Volatile
        var listener: ((Boolean) -> Unit)? = null

        private fun publish(on: Boolean) {
            isRunning = on
            val callback = listener ?: return
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                callback(on)
            }
        }
    }
}
