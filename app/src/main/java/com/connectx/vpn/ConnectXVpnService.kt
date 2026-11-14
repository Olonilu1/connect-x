package com.connectx.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLParameters
import javax.net.ssl.SNIHostName
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import mobile.Mobile

class ConnectXVpnService : VpnService() {

    companion object {
        const val TAG = "ConnectXVpnService"
        const val NOTIFICATION_CHANNEL_ID = "connectx_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_CONNECT = "com.connectx.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.connectx.vpn.DISCONNECT"
        const val EXTRA_TUNNELS = "tunnels_json"
        const val EXTRA_MTU = "mtu"

        var isRunning = AtomicBoolean(false)
        var stateCallback: ((String) -> Unit)? = null
    }

    data class Tunnel(
        val name: String,
        val dnsServer: String,
        val tunnelDomain: String,
        val publicKey: String,
        val port: Int,
        val sshHost: String = "",
        val sshPort: Int = 22,
        val sshUser: String = "",
        val sshPass: String = "",
        val sni: String = "",
        val payload: String = "",
        val mode: String = "dnstt",
        val udpgwPort: Int = 0
    ) {
        var client: mobile.DnsttClient? = null
        var udpGw: UdpGwClient? = null
        var restartFails = 0
        var sshSession: Session? = null
        var sshFails = 0
        val usesSsh: Boolean get() = sshUser.isNotEmpty()
    }

    private var tunnels: MutableList<Tunnel> = mutableListOf()
    private var lastFail = ""
    private var vpnInterface: ParcelFileDescriptor? = null
    private var mtu: Int = 1400

    private var runningThread: Thread? = null
    private var watchdogThread: Thread? = null
    private val shouldRun = AtomicBoolean(false)
    private var wakeLock: PowerManager.WakeLock? = null

    private val tcpConnections = ConcurrentHashMap<String, TcpConnection>()
    private val pendingConnections: MutableSet<String> = Collections.synchronizedSet(HashSet())
    private var synExecutor = Executors.newFixedThreadPool(16)
    private val handshakeSemaphore = Semaphore(3)
    private val roundRobin = AtomicInteger(0)
    @Volatile private var vpnOut: FileOutputStream? = null
    private val vpnOutLock = Any()
    private val ipIdent = AtomicInteger(0)
    private var udpExecutor: java.util.concurrent.ExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_CONNECT -> {
                val list = parseTunnels(intent.getStringExtra(EXTRA_TUNNELS) ?: "[]")
                mtu = intent.getIntExtra(EXTRA_MTU, 1400)
                if (list.isEmpty()) {
                    setState("error"); stopSelf(); return START_NOT_STICKY
                }
                tunnels = list.toMutableList()
                Thread { connect() }.start()
                START_STICKY
            }
            ACTION_DISCONNECT -> {
                disconnect(); START_NOT_STICKY
            }
            else -> {
                if (!isRunning.get()) stopSelf()
                START_NOT_STICKY
            }
        }
    }

    private fun parseTunnels(json: String): List<Tunnel> {
        return try {
            val arr = org.json.JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Tunnel(
                    name = o.optString("name", "tunnel"),
                    dnsServer = o.optString("dnsServer").ifEmpty { "8.8.8.8" },
                    tunnelDomain = o.optString("tunnelDomain"),
                    publicKey = o.optString("publicKey"),
                    port = 7001 + i,
                    sshHost = o.optString("sshHost"),
                    sshPort = (o.optString("sshPort").toIntOrNull() ?: 22).let { if (it in 1..65535) it else 22 },
                    sshUser = o.optString("sshUser"),
                    sshPass = o.optString("sshPass"),
                    sni = o.optString("sni"),
                    payload = o.optString("payload"),
                    mode = o.optString("mode").let { if (it in setOf("dnstt", "tls", "plain")) it else "dnstt" },
                    udpgwPort = (o.optString("udpgwPort").toIntOrNull() ?: 0).let { if (it in 1..65535) it else 0 }
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "bad tunnels json", e); emptyList()
        }
    }

    private fun setState(s: String) {
        android.os.Handler(android.os.Looper.getMainLooper()).post { stateCallback?.invoke(s) }
    }

    private fun isPortInUse(port: Int): Boolean {
        return try { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }; true }
        catch (e: Exception) { false }
    }

    /** Bring the SSH leg up inside a running dnstt tunnel (DNSTT+SSH mode). */
    private fun ensureSsh(t: Tunnel): Boolean {
        if (!t.usesSsh) return true
        if (t.sshSession?.isConnected == true) { ensureUdpGw(t); return true }
        return try {
            val host = t.sshHost.ifEmpty { t.tunnelDomain.removePrefix("ns-") }
            val jsch = JSch()
            // The dnstt tunnel's far end is an SSH server: dial the session straight
            // through the local tunnel listener instead of any proxy handshake.
                        val session = jsch.getSession(t.sshUser, host, t.sshPort)
            when (t.mode) {
                "tls" -> session.setSocketFactory(TlsPayloadSocketFactory(host, t.sshPort, t.sni, t.payload))
                "plain" -> session.setSocketFactory(PlainSocketFactory(host, t.sshPort))
                else -> session.setSocketFactory(TunnelSocketFactory(t.port))
            }
            session.setPassword(t.sshPass)
            session.setConfig("StrictHostKeyChecking", "no")
            session.setConfig("PreferredAuthentications", "password,keyboard-interactive,publickey")
            session.connect(60000)
            t.sshSession = session
            Log.d(TAG, "ssh up through tunnel ${t.port}")
            ensureUdpGw(t)
            true
        } catch (e: Exception) {
            Log.e(TAG, "ssh connect failed through tunnel ${t.port}", e)
            lastFail = e.message?.let { "ssh: ${it.take(90)}" } ?: "ssh failed"
            t.sshSession = null
            false
        }
    }

    /** SocketFactory that ignores the requested host/port and dials the local tunnel listener,
     *  whose far end is the tunnel server's own SSH daemon. */
    class TunnelSocketFactory(private val tunnelPort: Int) : com.jcraft.jsch.SocketFactory {
        override fun createSocket(host: String, port: Int) = Socket().apply {
            tcpNoDelay = true
            connect(InetSocketAddress("127.0.0.1", tunnelPort), 15000)
            soTimeout = 0
        }
        override fun getInputStream(socket: Socket) = socket.getInputStream()
        override fun getOutputStream(socket: Socket) = socket.getOutputStream()
    }

    /** Plain direct socket factory (no tunnel leg), for pure SSH profiles. */
    class PlainSocketFactory(private val dialHost: String, private val dialPort: Int) : com.jcraft.jsch.SocketFactory {
        override fun createSocket(host: String, port: Int) = Socket().apply {
            tcpNoDelay = true
            connect(InetSocketAddress(dialHost, dialPort), 15000)
            soTimeout = 0
        }
        override fun getInputStream(socket: Socket) = socket.getInputStream()
        override fun getOutputStream(socket: Socket) = socket.getOutputStream()
    }

    /** Direct TLS socket with SNI override and an HTTP payload injected right after the
     *  handshake: SSH then runs inside TLS, netmod SSH-TLS-Payload style. */
    class TlsPayloadSocketFactory(
        private val dialHost: String,
        private val dialPort: Int,
        private val sni: String,
        private val payload: String
    ) : com.jcraft.jsch.SocketFactory {
        private fun trustAllManagers(): Array<javax.net.ssl.TrustManager> {
            return arrayOf(object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            })
        }

        override fun createSocket(host: String, port: Int): Socket {
            val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
            ctx.init(null, trustAllManagers(), java.security.SecureRandom())
            val socket = ctx.socketFactory.createSocket() as javax.net.ssl.SSLSocket
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(dialHost, dialPort), 15000)
            socket.soTimeout = 0
            val sniHost = sni.ifEmpty { dialHost }
            val params: javax.net.ssl.SSLParameters = socket.sslParameters
            params.serverNames = listOf(javax.net.ssl.SNIHostName(sniHost))
            socket.sslParameters = params
            socket.startHandshake()
            val pl = expandPayload(payload, sniHost, dialHost, dialPort)
            if (pl.isNotEmpty()) {
                socket.getOutputStream().apply { write(pl.toByteArray(Charsets.ISO_8859_1)); flush() }
            }
            // Peek the first response bytes: an HTTP answer (e.g. 101 Switching
            // Protocols) must be drained before the SSH stream starts. Anything
            // else (the SSH banner itself) is pushed back for jsch.
            responseStream = null
            try {
                socket.soTimeout = 3000
                val inp = java.io.PushbackInputStream(socket.getInputStream(), 16384)
                val first = inp.read()
                if (first >= 0) {
                    if (first == 'H'.code) {
                        val sb = StringBuilder("H")
                        val deadline = System.currentTimeMillis() + 8000
                        while (true) {
                            val r = inp.read()
                            if (r < 0) break
                            sb.append(r.toChar())
                            if (sb.endsWith("\r\n\r\n")) break
                            if (System.currentTimeMillis() > deadline) break
                        }
                        responseStream = inp
                    } else {
                        inp.unread(first)
                        responseStream = inp
                    }
                } else {
                    responseStream = inp
                }
            } catch (e: Exception) {
                responseStream = null
            } finally {
                try { socket.soTimeout = 0 } catch (e: Exception) {}
            }
            return socket
        }
        private var responseStream: java.io.PushbackInputStream? = null
        override fun getInputStream(socket: Socket) = responseStream ?: socket.getInputStream()
        override fun getOutputStream(socket: Socket) = socket.getOutputStream()
    }

    private fun verifySsh(t: Tunnel): Boolean = try {
        val host = t.sshHost.ifEmpty { t.tunnelDomain.removePrefix("ns-") }
        val conn = SshConnection({ t.sshSession }, "example.com", 80)
        conn.connect()
    } catch (e: Exception) {
        Log.e(TAG, "ssh verify failed", e)
        false
    }

    /** UDP gateway over the SSH leg (badvpn udpgw) so UDP apps get through the tunnel. */
    private fun ensureUdpGw(t: Tunnel) {
        if (!t.usesSsh || t.udpGw != null) return
        val session = t.sshSession ?: return
        val ports = if (t.udpgwPort > 0) listOf(t.udpgwPort) else listOf(7300, 446)
        for (port in ports) {
            try {
                val channel = session.openChannel("direct-tcpip") as com.jcraft.jsch.ChannelDirectTCPIP
                channel.setHost("127.0.0.1")
                channel.setPort(port)
                channel.connect(8000)
                val gw = UdpGwClient(channel.inputStream, channel.outputStream)
                gw.listener = object : UdpGwClient.Listener {
                    override fun onPacket(localIp: InetAddress, localPort: Int, remoteIp: InetAddress, remotePort: Int, data: ByteArray) {
                        try {
                            val out = vpnOut ?: return
                            val ident = ipIdent.updateAndGet { v -> if (v >= 0xffff) 0 else v + 1 }
                            val udp = UDPHeader(remotePort, localPort, 8 + data.size, 0, data)
                            val ip = IPv4Header(4, 5, 20 + 8 + data.size, ident, 0, 0, 64, 17, 0,
                                remoteIp, localIp, udp.toByteArray(remoteIp, localIp))
                            synchronized(vpnOutLock) { out.write(ip.toByteArrayForUdp()); out.flush() }
                        } catch (e: Exception) { Log.e(TAG, "udpgw reply write failed", e) }
                    }
                    override fun onError(reason: String) { Log.e(TAG, "udpgw $port: $reason") }
                }
                gw.start()
                t.udpGw = gw
                Log.d(TAG, "udpgw up on 127.0.0.1:$port via ssh for ${t.name}")
                return
            } catch (e: Exception) {
                Log.d(TAG, "udpgw port $port unavailable: ${e.message?.take(60)}")
            }
        }
        Log.d(TAG, "no udpgw reachable for ${t.name}; UDP stays local")
    }

    /** Race a few well-known resolvers and keep the fastest one: dnstt throughput is
     *  capped by the round-trip time to the resolver, so a fast resolver is a real speed-up. */
    private fun pickResolver(t: Tunnel): String {
        val candidates = linkedSetOf("1.1.1.1", "8.8.8.8", "9.9.9.9", t.dnsServer.substringBefore(":"))
        var best = t.dnsServer.substringBefore(":")
        var bestMs = Long.MAX_VALUE
        val lock = Any()
        val threads = candidates.map { cand ->
            Thread {
                var ms = Long.MAX_VALUE
                try {
                    val s = DatagramSocket()
                    protect(s)
                    s.soTimeout = 800
                    val q = dnsProbeQuery()
                    val start = System.currentTimeMillis()
                    s.send(DatagramPacket(q, q.size, InetAddress.getByName(cand), 53))
                    val buf = ByteArray(512)
                    val resp = DatagramPacket(buf, buf.size)
                    s.receive(resp)
                    ms = System.currentTimeMillis() - start
                    s.close()
                } catch (e: Exception) { ms = Long.MAX_VALUE }
                synchronized(lock) { if (ms < bestMs) { bestMs = ms; best = cand } }
            }.apply { isDaemon = true }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(1200) }
        return best
    }

    private fun dnsProbeQuery(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x4a, 0x4a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        for (label in listOf("example", "com")) {
            out.write(label.length); out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0); out.write(byteArrayOf(0, 1, 0, 1))
        return out.toByteArray()
    }

    private fun startClient(t: Tunnel): Boolean {
        if (t.tunnelDomain.isEmpty() || t.publicKey.isEmpty()) return false
        try {
            stopClient(t)
            if (isPortInUse(t.port)) {
                Log.w(TAG, "port ${t.port} still in use")
                return false
            }
            Log.d(TAG, "starting dnstt client: dns=${t.dnsServer} domain=${t.tunnelDomain} port=${t.port}")
            val resolver = pickResolver(t)
            Log.d(TAG, "dnstt resolver for ${t.port}: $resolver")
            t.client = Mobile.newClient(resolver, t.tunnelDomain, t.publicKey, "127.0.0.1:${t.port}")
            t.client?.start()
            Thread.sleep(150)
            val ok = t.client?.isRunning ?: false
            Log.d(TAG, "client ${t.port} running=$ok")
            return ok
        } catch (e: Exception) {
            Log.e(TAG, "failed to start client ${t.port}", e)
            lastFail = e.message?.let { "slowdns: ${it.take(90)}" } ?: "slowdns failed"
            return false
        }
    }

    private fun stopClient(t: Tunnel) {
        t.client?.let {
            try { it.stop() } catch (e: Exception) { Log.e(TAG, "stop client error", e) }
        }
        t.client = null
        t.sshSession?.let {
            try { it.disconnect() } catch (_: Exception) {}
        }
        t.sshSession = null
        t.udpGw?.let { try { it.stop() } catch (_: Exception) {} }
        t.udpGw = null
    }

    private fun socksHandshakeOk(port: Int, timeoutMs: Int): Boolean {
        return try {
            Socket().use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress("127.0.0.1", port), 3000)
                s.getOutputStream().apply { write(byteArrayOf(0x05, 0x01, 0x00)); flush() }
                val resp = ByteArray(2)
                var n = 0
                val inp = s.getInputStream()
                while (n < 2) { val r = inp.read(); if (r < 0) break; resp[n++] = r.toByte() }
                n == 2 && resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()
            }
        } catch (e: Exception) { false }
    }

    private fun verifyTunnel(port: Int, timeoutMs: Int): Boolean {
        return try {
            Socket().use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress("127.0.0.1", port), 5000)
                val out = s.getOutputStream(); val inp = s.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                val auth = ByteArray(2)
                if (inp.read(auth) != 2 || auth[0] != 0x05.toByte() || auth[1] != 0x00.toByte()) return false
                val host = "api.ipify.org"
                val req = ByteArray(7 + host.length)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = host.length.toByte()
                System.arraycopy(host.toByteArray(), 0, req, 5, host.length)
                req[5 + host.length] = 0; req[6 + host.length] = 80.toByte()
                out.write(req); out.flush()
                val resp = ByteArray(10)
                if (inp.read(resp, 0, 4) < 4 || resp[1] != 0x00.toByte()) return false
                when (resp[3]) {
                    0x01.toByte() -> inp.read(ByteArray(6))
                    0x03.toByte() -> { val dl = inp.read(); inp.read(ByteArray(dl + 2)) }
                    0x04.toByte() -> inp.read(ByteArray(18))
                }
                out.write("GET /?format=text HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
                out.flush()
                val buf = ByteArray(256)
                val n = inp.read(buf)
                n > 0 && String(buf, 0, n).contains("200")
            }
        } catch (e: Exception) { false }
    }

    private fun connect() {
        if (isRunning.get()) { Log.d(TAG, "already running"); return }
        try {
            setState("connecting")
            createNotificationChannel()
            startFg(createNotification("connecting"))
            acquireWakeLock()

            val builder = Builder()
                .setSession("Connect X")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(tunnels[0].dnsServer.substringBefore(":"))
                .setMtu(mtu)
                .setBlocking(true)
            builder.addDisallowedApplication(packageName)

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "failed to establish vpn interface")
                setState("error: vpn permission needed"); releaseWakeLock()
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return
            }
            Thread.sleep(500)

            udpExecutor = Executors.newSingleThreadExecutor()
            var startedAny = false
            val live = mutableListOf<Tunnel>()
            for (t in tunnels) {
                val started = when (t.mode) {
                    "dnstt" -> startClient(t) && (if (t.usesSsh) ensureSsh(t) else socksHandshakeOk(t.port, 5000))
                    else -> t.usesSsh && ensureSsh(t)
                }
                if (started) {
                    live.add(t); startedAny = true
                } else {
                    Log.e(TAG, "tunnel ${t.name} on port ${t.port} failed to start")
                }
            }
            if (!startedAny) {
                Log.e(TAG, "no tunnel started")
                setState("error: ${lastFail.ifEmpty { "no tunnel connected" }}")
                tunnels.forEach { stopClient(it) }
                vpnInterface?.close(); vpnInterface = null
                releaseWakeLock(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return
            }
            tunnels = live

            val first = tunnels[0].port
            val verified = if (tunnels[0].usesSsh) verifySsh(tunnels[0]) else verifyTunnel(first, 20000)
            if (!verified) {
                Log.e(TAG, "tunnel verification failed")
                setState("error: ${lastFail.ifEmpty { "tunnel check failed" }}")
                tunnels.forEach { stopClient(it) }
                vpnInterface?.close(); vpnInterface = null
                releaseWakeLock(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return
            }
            Log.d(TAG, "tunnel verified, ${tunnels.size} active")

            isRunning.set(true)
            shouldRun.set(true)
            updateNotification("connected")
            setState("connected")

            runningThread = Thread { runVpnLoop() }.also { it.start() }
            watchdogThread = Thread { runWatchdog() }.also { it.start() }
        } catch (e: Exception) {
            Log.e(TAG, "connect failed", e)
            setState("error: ${e.message?.take(90) ?: "connect failed"}")
            disconnect()
        }
    }

    private fun startFg(n: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun runWatchdog() {
        while (shouldRun.get()) {
            Thread.sleep(10000)
            if (!shouldRun.get()) break
            for (t in tunnels.toList()) {
                if (t.usesSsh) {
                    val sshAlive = t.sshSession?.isConnected == true
                    if (!sshAlive) {
                        Log.w(TAG, "ssh leg ${t.name} down, re-dialing")
                        if (!ensureSsh(t)) {
                            t.sshFails++
                            if (t.sshFails >= 3) {
                                Log.e(TAG, "ssh leg ${t.name} dropped after 3 failed re-dials")
                                stopClient(t)
                                tunnels.remove(t)
                                continue
                            }
                        } else {
                            t.sshFails = 0
                        }
                    } else {
                        t.sshFails = 0
                    }
                }
                val alive = t.client?.isRunning ?: false
                if (!alive) {
                    Log.w(TAG, "tunnel ${t.name} (${t.port}) died, restarting")
                    val restarted = when (t.mode) {
                        "dnstt" -> startClient(t) && (if (t.usesSsh) ensureSsh(t) else socksHandshakeOk(t.port, 5000))
                        else -> t.usesSsh && ensureSsh(t)
                    }
                    if (restarted) {
                        t.restartFails = 0
                    } else {
                        t.restartFails++
                        if (t.restartFails >= 3) {
                            Log.e(TAG, "tunnel ${t.name} dropped after 3 failed restarts")
                            stopClient(t)
                            tunnels.remove(t)
                        }
                    }
                } else {
                    t.restartFails = 0
                }
            }
            if (tunnels.isEmpty() && shouldRun.get()) {
                Log.e(TAG, "all tunnels dead")
                setState("error")
                disconnect()
                break
            }
        }
    }

    private fun runVpnLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(vpnFd)
        val outputStream = FileOutputStream(vpnFd)
        vpnOut = outputStream
        val packet = ByteBuffer.allocate(32767)
        var lastCleanup = System.currentTimeMillis()
        try {
            while (shouldRun.get()) {
                val length = inputStream.channel.read(packet)
                if (length > 0) {
                    packet.flip()
                    val packetBytes = ByteArray(length)
                    packet.get(packetBytes)
                    val ipHeader = IPv4Header.parse(packetBytes)
                    if (ipHeader != null) {
                        when (ipHeader.protocol) {
                            6.toByte() -> processTcpPacket(ipHeader, outputStream)
                            17.toByte() -> processUdpPacket(ipHeader, outputStream)
                        }
                    }
                    packet.clear()
                } else {
                    Thread.sleep(1)
                }
                val now = System.currentTimeMillis()
                if (now - lastCleanup > 10000) {
                    lastCleanup = now
                    val closed = tcpConnections.entries.filter { it.value.state == TcpConnection.State.CLOSED }.map { it.key }
                    for (key in closed) tcpConnections.remove(key)
                }
            }
        } catch (e: Exception) {
            if (shouldRun.get()) Log.e(TAG, "vpn loop error", e)
        } finally {
            try { inputStream.close(); outputStream.close() } catch (e: Exception) { }
            synchronized(vpnOutLock) { vpnOut = null }
        }
    }

    private fun pickPort(): Int {
        val list = tunnels
        if (list.isEmpty()) return 7001
        val i = Math.floorMod(roundRobin.incrementAndGet(), list.size)
        return list[i].port
    }

    private fun processTcpPacket(ipHeader: IPv4Header, vpnOutput: FileOutputStream) {
        val tcpHeader = TCPHeader.parse(ipHeader.payload) ?: return
        val connectionId = "${ipHeader.sourceIp}:${tcpHeader.sourcePort}-${ipHeader.destinationIp}:${tcpHeader.destinationPort}"
        if (tcpHeader.isSYN && !tcpHeader.isACK) {
            if (tcpConnections.containsKey(connectionId) || !pendingConnections.add(connectionId)) return
            val destHostAddress = ipHeader.destinationIp.hostAddress ?: run {
                pendingConnections.remove(connectionId); return
            }
            val clientSeqNum = tcpHeader.sequenceNumber
            val srcIp = ipHeader.sourceIp; val srcPort = tcpHeader.sourcePort
            val dstIp = ipHeader.destinationIp; val dstPort = tcpHeader.destinationPort
            synExecutor.submit {
                try {
                    if (!handshakeSemaphore.tryAcquire(10, java.util.concurrent.TimeUnit.SECONDS)) {
                        Log.w(TAG, "handshake queue full, dropping: $connectionId")
                        return@submit
                    }
                    try {
                        val port = pickPort()
                        val t = tunnels.firstOrNull { it.port == port } ?: tunnels.firstOrNull()
                        val transport: Transport = if (t != null && t.usesSsh) {
                            SshConnection({ t.sshSession }, destHostAddress, dstPort)
                        } else {
                            Socks5Client("127.0.0.1", port, destHostAddress, dstPort, null, null)
                        }
                        val tcpConnection = TcpConnection(srcIp, srcPort, dstIp, dstPort, vpnOutput, transport)
                        if (tcpConnection.handleSyn(clientSeqNum)) {
                            tcpConnections[connectionId] = tcpConnection
                            Log.d(TAG, "new tcp connection: $connectionId via port $port")
                        } else {
                            Log.e(TAG, "failed to establish: $connectionId")
                        }
                    } finally {
                        handshakeSemaphore.release()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "syn processing error for $connectionId", e)
                } finally {
                    pendingConnections.remove(connectionId)
                }
            }
        } else if (tcpHeader.isFIN) {
            tcpConnections[connectionId]?.handleFin(tcpHeader.sequenceNumber)
            tcpConnections.remove(connectionId)
        } else if (tcpHeader.isRST) {
            tcpConnections[connectionId]?.close()
            tcpConnections.remove(connectionId)
        } else if (tcpHeader.isACK) {
            tcpConnections[connectionId]?.handleAck(tcpHeader.sequenceNumber, tcpHeader.acknowledgmentNumber, tcpHeader.payload)
        }
    }

    private fun processUdpPacket(ipHeader: IPv4Header, vpnOutput: FileOutputStream) {
        val udpHeader = UDPHeader.parse(ipHeader.payload) ?: return
        if (udpHeader.destinationPort == 53) { forwardDns(ipHeader, udpHeader, vpnOutput); return }
        val gw = tunnels.firstNotNullOfOrNull { it.udpGw } ?: return
        val data = udpHeader.payload
        if (data.isEmpty() || data.size > 1300) return
        val sender = udpExecutor ?: return
        val srcIp = ipHeader.sourceIp; val srcPort = udpHeader.sourcePort
        val dstIp = ipHeader.destinationIp; val dstPort = udpHeader.destinationPort
        sender.submit {
            try { gw.sendPacket(srcIp, srcPort, dstIp, dstPort, data) } catch (e: Exception) { Log.e(TAG, "udp send failed", e) }
        }
    }

    private fun forwardDns(ipHeader: IPv4Header, udpHeader: UDPHeader, vpnOutput: FileOutputStream) {
        Thread {
            try {
                val dnsSocket = DatagramSocket()
                protect(dnsSocket)
                val dnsServerAddr = InetAddress.getByName(tunnels[0].dnsServer)
                val queryPacket = DatagramPacket(udpHeader.payload, udpHeader.payload.size, dnsServerAddr, 53)
                dnsSocket.soTimeout = 5000
                dnsSocket.send(queryPacket)
                val responseBuffer = ByteArray(4096)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                dnsSocket.receive(responsePacket)
                dnsSocket.close()
                val responseData = responseBuffer.copyOf(responsePacket.length)
                val responseUdp = UDPHeader(53, udpHeader.sourcePort, 8 + responseData.size, 0, responseData)
                val responseIp = IPv4Header(4, 5, 20 + 8 + responseData.size, ipHeader.identification + 1, 0, 0, 64, 17, 0,
                    ipHeader.destinationIp, ipHeader.sourceIp, responseUdp.toByteArray(ipHeader.destinationIp, ipHeader.sourceIp))
                synchronized(vpnOutput) {
                    vpnOutput.write(responseIp.toByteArrayForUdp()); vpnOutput.flush()
                }
            } catch (e: Exception) {
                Log.e(TAG, "dns forwarding failed", e)
            }
        }.start()
    }

    private fun disconnect() {
        Log.d(TAG, "disconnecting")
        shouldRun.set(false)
        setState("disconnecting")
        runningThread?.interrupt(); runningThread = null
        watchdogThread?.interrupt(); watchdogThread = null
        pendingConnections.clear()
        synExecutor.shutdownNow()
        synExecutor = Executors.newFixedThreadPool(16)
        udpExecutor?.shutdownNow(); udpExecutor = null
        synchronized(vpnOutLock) { vpnOut = null }
        tcpConnections.values.forEach { it.close() }
        tcpConnections.clear()
        try { vpnInterface?.close() } catch (e: Exception) { Log.e(TAG, "close vpn error", e) }
        vpnInterface = null
        tunnels.forEach { stopClient(it) }
        releaseWakeLock()
        isRunning.set(false)
        setState("disconnected")
        stopForeground(STOP_FOREGROUND_REMOVE)
        val nm = getSystemService(NotificationManager::class.java)
        nm?.cancel(NOTIFICATION_ID)
        stopSelf()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(NOTIFICATION_CHANNEL_ID, "SlowDNS VPN", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shows when the VPN is connected"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(state: String): Notification {
        val openAppIntent = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val disconnectIntent = PendingIntent.getService(this, 1,
            Intent(this, ConnectXVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val label = if (tunnels.size > 1) "SlowDNS VPN (${tunnels.size} tunnels)" else "SlowDNS VPN"
        val (title, text, icon) = when (state) {
            "connecting" -> Triple("$label connecting", "establishing tunnel", android.R.drawable.ic_popup_sync)
            "connected" -> Triple("$label connected", "tunneling via ${tunnels[0].dnsServer}", android.R.drawable.ic_lock_lock)
            "disconnecting" -> Triple("$label disconnecting", "closing tunnel", android.R.drawable.ic_popup_sync)
            else -> Triple(label, "status: $state", android.R.drawable.ic_lock_lock)
        }
        val b = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title).setContentText(text)
            .setSmallIcon(icon).setContentIntent(openAppIntent)
            .setOngoing(true).setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true).setSilent(true)
        if (state == "connected") {
            b.addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectIntent)
        }
        return b.build()
    }

    private fun updateNotification(state: String) {
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, createNotification(state))
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ConnectXVpnService::WakeLock")
        }
        wakeLock?.let { if (!it.isHeld) it.acquire() }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }
}

/** Expand netmod-style payload tokens: [crlf]/[lf]/[cr], [ssh_host]/[ssh_port],
 *  [host]/[port], [protocol], [rnd]. */
fun expandPayload(tpl: String, hostHeader: String, sshHost: String, sshPort: Int): String {
    if (tpl.isEmpty()) return ""
    var p = tpl
        .replace("[protocol]", "HTTP/1.1")
        .replace("[ssh_host]", sshHost)
        .replace("[ssh_port]", sshPort.toString())
        .replace("[host]", hostHeader)
        .replace("[port]", sshPort.toString())
        .replace("[rnd]", java.util.UUID.randomUUID().toString().replace("-", ""))
    p = p.replace("[crlf]", "\r\n").replace("[cr]", "\r").replace("[lf]", "\n")
    return p
}
