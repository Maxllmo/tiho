package app.proxyhub.tv

import android.util.Base64
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class SocksBridge(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val proxyUser: String,
    private val proxyPass: String,
    private val protect: (Socket) -> Boolean,
    private val protectUdp: (DatagramSocket) -> Boolean
) {
    private val running = AtomicBoolean(true)
    private val pool: ExecutorService = Executors.newCachedThreadPool()
    private var server: ServerSocket? = null
    val port: Int get() = server?.localPort ?: 0

    fun start() {
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress("127.0.0.1", 0))
        server = socket
        pool.execute {
            while (running.get()) {
                val client = try {
                    socket.accept()
                } catch (_: Exception) {
                    break
                }
                pool.execute { handle(client) }
            }
        }
    }

    fun stop() {
        running.set(false)
        try {
            server?.close()
        } catch (_: Exception) {
        }
        pool.shutdownNow()
    }

    private fun handle(client: Socket) {
        client.tcpNoDelay = true
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()
            val methods = input.read()
            if (methods <= 0) return
            val offered = ByteArray(methods)
            if (readFully(input, offered) < 0) return
            if (offered.none { it == 0.toByte() }) {
                output.write(byteArrayOf(5, 0xFF.toByte()))
                return
            }
            output.write(byteArrayOf(5, 0))
            output.flush()

            val header = ByteArray(3)
            if (readFully(input, header) < 0) return
            if (header[0] != 5.toByte()) return
            val cmd = header[1].toInt() and 0xff
            val dest = readAddr(input) ?: return
            when (cmd) {
                1 -> connect(client, input, output, dest.first, dest.second)
                3 -> udp(client, output)
                else -> reply(output, 7)
            }
        } catch (error: Exception) {
            Log.d(TAG, "socks", error)
        } finally {
            try {
                client.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun connect(client: Socket, input: InputStream, output: OutputStream, host: String, port: Int) {
        if (isFake(host)) {
            reply(output, 1)
            return
        }
        if (isIp(host) && !shouldBypass(host)) {
            reply(output, 0)
            val peeked = peek(client, input)
            val name = sniff(peeked) ?: host
            val remote = open(name, port, shouldBypass(name)) ?: run {
                client.close()
                return
            }
            splice(client, remote, peeked)
            return
        }
        val remote = open(host, port, shouldBypass(host)) ?: run {
            reply(output, 5)
            return
        }
        reply(output, 0)
        splice(client, remote, ByteArray(0))
    }

    private fun open(host: String, port: Int, direct: Boolean): Socket? {
        return try {
            if (direct || host.equals(proxyHost, ignoreCase = true)) {
                dial(host, port)
            } else {
                httpConnect(host, port)
            }
        } catch (error: Exception) {
            Log.d(TAG, "open $host:$port direct=$direct", error)
            null
        }
    }

    private fun dial(host: String, port: Int): Socket {
        val socket = Socket()
        protect(socket)
        socket.tcpNoDelay = true
        socket.connect(InetSocketAddress(host, port), 10_000)
        return socket
    }

    private fun httpConnect(host: String, port: Int): Socket {
        val socket = dial(proxyHost, proxyPort)
        val output = socket.getOutputStream()
        val auth = if (proxyUser.isNotEmpty()) {
            val token = Base64.encodeToString(
                "$proxyUser:$proxyPass".toByteArray(StandardCharsets.UTF_8),
                Base64.NO_WRAP
            )
            "Proxy-Authorization: Basic $token\r\n"
        } else {
            ""
        }
        val request = "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n$auth" +
            "Proxy-Connection: keep-alive\r\n\r\n"
        output.write(request.toByteArray(StandardCharsets.ISO_8859_1))
        output.flush()
        val response = readHeaders(socket.getInputStream())
        val line = response.lineSequence().firstOrNull().orEmpty()
        if (!line.contains(" 200 ")) {
            socket.close()
            throw IllegalStateException(line.ifBlank { "proxy rejected" })
        }
        return socket
    }

    private fun splice(client: Socket, remote: Socket, prefix: ByteArray) {
        if (prefix.isNotEmpty()) {
            remote.getOutputStream().write(prefix)
            remote.getOutputStream().flush()
        }
        val up = Thread {
            pump(client.getInputStream(), remote.getOutputStream())
        }
        val down = Thread {
            pump(remote.getInputStream(), client.getOutputStream())
        }
        up.start()
        down.start()
        up.join()
        down.join()
        try {
            remote.close()
        } catch (_: Exception) {
        }
    }

    private fun pump(from: InputStream, to: OutputStream) {
        try {
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(buf, 0, n)
                to.flush()
            }
        } catch (_: Exception) {
        } finally {
            try {
                to.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun peek(client: Socket, input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(2048)
        val deadline = System.nanoTime() + 500_000_000L
        client.soTimeout = 250
        try {
            while (out.size() < 8192 && System.nanoTime() < deadline) {
                val n = try {
                    input.read(buf)
                } catch (_: SocketTimeoutException) {
                    if (out.size() > 0) break else continue
                }
                if (n < 0) break
                out.write(buf, 0, n)
                val data = out.toByteArray()
                if (tlsReady(data) || httpHost(data) != null) break
                if (data.isNotEmpty() && data[0] != 0x16.toByte() && data[0] !in 0x41..0x5A && data[0] !in 0x61..0x7A) {
                    break
                }
            }
        } finally {
            try {
                client.soTimeout = 0
            } catch (_: Exception) {
            }
        }
        return out.toByteArray()
    }

    private fun sniff(data: ByteArray): String? = sni(data) ?: httpHost(data)

    private fun udp(client: Socket, output: OutputStream) {
        val udp = DatagramSocket(null)
        udp.reuseAddress = true
        udp.bind(InetSocketAddress("127.0.0.1", 0))
        replyBound(output, udp.localPort)
        val relay = DatagramSocket()
        protectUdp(udp)
        protectUdp(relay)
        val clientAddr = arrayOfNulls<InetSocketAddress>(1)
        val worker = Thread {
            val buf = ByteArray(65535)
            while (running.get() && !client.isClosed) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    udp.soTimeout = 1000
                    udp.receive(packet)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    break
                }
                clientAddr[0] = InetSocketAddress(packet.address, packet.port)
                val parsed = parseUdp(packet.data, packet.length) ?: continue
                if (!shouldBypass(parsed.host) && parsed.port != 53) continue
                try {
                    relay.send(DatagramPacket(parsed.data, parsed.data.size, InetSocketAddress(parsed.host, parsed.port)))
                } catch (_: Exception) {
                }
            }
        }
        val back = Thread {
            val buf = ByteArray(65535)
            while (running.get() && !client.isClosed) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    relay.soTimeout = 1000
                    relay.receive(packet)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    break
                }
                val who = clientAddr[0] ?: continue
                val wrapped = wrapUdp(packet.address, packet.port, packet.data, packet.length)
                try {
                    udp.send(DatagramPacket(wrapped, wrapped.size, who))
                } catch (_: Exception) {
                }
            }
        }
        worker.start()
        back.start()
        try {
            while (running.get()) {
                client.soTimeout = 60_000
                if (client.getInputStream().read() < 0) break
            }
        } catch (_: Exception) {
        }
        udp.close()
        relay.close()
        worker.join(1000)
        back.join(1000)
    }

    private fun shouldBypass(host: String): Boolean {
        val raw = host.trim().trimEnd('.').lowercase()
        if (raw.isEmpty() || raw == "localhost" || raw == proxyHost.lowercase()) return true
        if (isIp(raw)) return isPrivate(raw)
        val ascii = try {
            java.net.IDN.toASCII(raw)
        } catch (_: Exception) {
            raw
        }
        if (ascii == "ru" || ascii.endsWith(".ru")) return true
        if (ascii == "xn--p1ai" || ascii.endsWith(".xn--p1ai") || raw == "рф" || raw.endsWith(".рф")) return true
        return false
    }

    private fun isPrivate(host: String): Boolean {
        val ip = try {
            InetAddress.getByName(host)
        } catch (_: Exception) {
            return false
        }
        if (ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress) return true
        val b = ip.address
        if (b.size == 16) {
            val first = b[0].toInt() and 0xff
            return first and 0xfe == 0xfc
        }
        val a = b[0].toInt() and 0xff
        val c = b[1].toInt() and 0xff
        return a == 10 || a == 127 || (a == 172 && c in 16..31) || (a == 192 && c == 168) || (a == 169 && c == 254)
    }

    private fun isFake(host: String): Boolean {
        if (!isIp(host)) return false
        val b = try {
            InetAddress.getByName(host).address
        } catch (_: Exception) {
            return false
        }
        if (b.size != 4) return false
        val a = b[0].toInt() and 0xff
        val c = b[1].toInt() and 0xff
        if (a == 100 && c in 64..127) return true
        return a == 198 && (c == 18 || c == 19)
    }

    private fun isIp(host: String): Boolean {
        return host.contains(':') || host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
    }

    private data class UdpMsg(val host: String, val port: Int, val data: ByteArray)

    private fun parseUdp(buf: ByteArray, length: Int): UdpMsg? {
        if (length < 4 || buf[2] != 0.toByte()) return null
        val atyp = buf[3].toInt() and 0xff
        var i = 4
        val host = when (atyp) {
            1 -> {
                if (i + 4 > length) return null
                val addr = InetAddress.getByAddress(buf.copyOfRange(i, i + 4)).hostAddress ?: return null
                i += 4
                addr
            }
            3 -> {
                if (i >= length) return null
                val n = buf[i].toInt() and 0xff
                i += 1
                if (i + n > length) return null
                val name = String(buf, i, n, StandardCharsets.UTF_8)
                i += n
                name
            }
            4 -> {
                if (i + 16 > length) return null
                val addr = InetAddress.getByAddress(buf.copyOfRange(i, i + 16)).hostAddress ?: return null
                i += 16
                addr
            }
            else -> return null
        }
        if (i + 2 > length) return null
        val port = ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
        i += 2
        return UdpMsg(host, port, buf.copyOfRange(i, length))
    }

    private fun wrapUdp(address: InetAddress, port: Int, data: ByteArray, length: Int): ByteArray {
        val raw = address.address
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0, 0, 0))
        if (raw.size == 4) {
            out.write(1)
            out.write(raw)
        } else {
            out.write(4)
            out.write(raw)
        }
        out.write((port shr 8) and 0xff)
        out.write(port and 0xff)
        out.write(data, 0, length)
        return out.toByteArray()
    }

    private fun readAddr(input: InputStream): Pair<String, Int>? {
        val atyp = input.read()
        val host = when (atyp) {
            1 -> {
                val b = ByteArray(4)
                if (readFully(input, b) < 0) return null
                InetAddress.getByAddress(b).hostAddress
            }
            3 -> {
                val n = input.read()
                if (n < 0) return null
                val b = ByteArray(n)
                if (readFully(input, b) < 0) return null
                String(b, StandardCharsets.UTF_8)
            }
            4 -> {
                val b = ByteArray(16)
                if (readFully(input, b) < 0) return null
                InetAddress.getByAddress(b).hostAddress
            }
            else -> return null
        } ?: return null
        val pb = ByteArray(2)
        if (readFully(input, pb) < 0) return null
        val port = ((pb[0].toInt() and 0xff) shl 8) or (pb[1].toInt() and 0xff)
        return host to port
    }

    private fun reply(output: OutputStream, code: Int) {
        output.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun replyBound(output: OutputStream, port: Int) {
        output.write(
            byteArrayOf(
                5, 0, 0, 1, 127, 0, 0, 1,
                ((port shr 8) and 0xff).toByte(),
                (port and 0xff).toByte()
            )
        )
        output.flush()
    }

    private fun readFully(input: InputStream, buf: ByteArray): Int {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) return -1
            off += n
        }
        return off
    }

    private fun readHeaders(input: InputStream): String {
        val out = ByteArrayOutputStream()
        var prev = 0
        while (out.size() < 8192) {
            val b = input.read()
            if (b < 0) break
            out.write(b)
            if (prev == '\r'.code && b == '\n'.code) {
                val arr = out.toByteArray()
                val n = arr.size
                if (n >= 4 && arr[n - 4] == '\r'.code.toByte() && arr[n - 3] == '\n'.code.toByte() &&
                    arr[n - 2] == '\r'.code.toByte() && arr[n - 1] == '\n'.code.toByte()
                ) {
                    break
                }
            }
            prev = b
        }
        return out.toString(StandardCharsets.ISO_8859_1)
    }

    private fun tlsReady(data: ByteArray): Boolean {
        if (data.size < 5 || data[0] != 0x16.toByte()) return false
        val len = ((data[3].toInt() and 0xff) shl 8) or (data[4].toInt() and 0xff)
        return data.size >= 5 + len
    }

    private fun sni(data: ByteArray): String? {
        if (!tlsReady(data)) return null
        var i = 5
        if (i + 4 > data.size || data[i] != 1.toByte()) return null
        i += 4
        if (i + 34 > data.size) return null
        i += 34
        if (i >= data.size) return null
        val session = data[i].toInt() and 0xff
        i += 1 + session
        if (i + 2 > data.size) return null
        val ciphers = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
        i += 2 + ciphers
        if (i >= data.size) return null
        val comp = data[i].toInt() and 0xff
        i += 1 + comp
        if (i + 2 > data.size) return null
        val extLen = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
        i += 2
        val end = minOf(data.size, i + extLen)
        while (i + 4 <= end) {
            val type = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
            val len = ((data[i + 2].toInt() and 0xff) shl 8) or (data[i + 3].toInt() and 0xff)
            i += 4
            if (i + len > data.size) return null
            if (type == 0 && len >= 5) {
                var j = i + 2
                val nameType = data[j].toInt() and 0xff
                val nameLen = ((data[j + 1].toInt() and 0xff) shl 8) or (data[j + 2].toInt() and 0xff)
                j += 3
                if (nameType == 0 && j + nameLen <= data.size) {
                    return String(data, j, nameLen, StandardCharsets.US_ASCII)
                }
            }
            i += len
        }
        return null
    }

    private fun httpHost(data: ByteArray): String? {
        if (data.isEmpty()) return null
        val text = String(data, StandardCharsets.ISO_8859_1)
        val verb = text.takeWhile { it != ' ' }
        if (verb !in setOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH")) return null
        val match = Regex("(?im)^Host:\\s*([^\\s:]+)").find(text) ?: return null
        return match.groupValues[1]
    }

    companion object {
        private const val TAG = "ProxyHubTV"
    }
}
