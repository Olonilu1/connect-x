package com.connectx.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * badvpn UDP gateway client (protocol v1) over a stream (SSH direct-tcpip channel).
 * Maps TUN UDP flows to gateway connection ids and writes replies back to the TUN.
 * Wire: 2-byte little-endian length, then [flags u8][conid u16le][ip 4B network][port u16le][len u16le][data].
 */
class UdpGwClient(private val input: InputStream, private val output: OutputStream) {

    interface Listener {
        fun onPacket(localIp: InetAddress, localPort: Int, remoteIp: InetAddress, remotePort: Int, data: ByteArray)
        fun onError(reason: String)
    }

    private val running = AtomicBoolean(false)
    private val writeLock = Any()
    private val flows = ConcurrentHashMap<String, Int>()
    private val reverse = ConcurrentHashMap<Int, Pair<InetAddress, Int>>()
    private val nextConId = AtomicInteger(0)
    var listener: Listener? = null

    fun start() {
        if (running.getAndSet(true)) return
        Thread({ readLoop() }, "udpgw-read").apply { isDaemon = true }.start()
        Thread({
            while (running.get()) {
                try { Thread.sleep(10000) } catch (e: InterruptedException) { return@Thread }
                if (running.get()) sendKeepalive()
            }
        }, "udpgw-keepalive").apply { isDaemon = true }.start()
    }

    fun stop() {
        running.set(false)
        try { input.close() } catch (_: Exception) {}
        try { output.close() } catch (_: Exception) {}
    }

    fun sendPacket(localIp: InetAddress, localPort: Int, remoteIp: InetAddress, remotePort: Int, data: ByteArray): Boolean {
        if (!running.get() || remoteIp.address.size != 4 || data.isEmpty()) return false
        val key = localIp.hostAddress + ":" + localPort + "|" + remoteIp.hostAddress + ":" + remotePort
        var conid = flows[key]
        if (conid == null) {
            conid = nextConId.updateAndGet { prev -> if (prev >= 65535) 1 else prev + 1 }
            flows[key] = conid
            reverse[conid] = Pair(localIp, localPort)
        }
        val payload = ByteArray(11 + data.size)
        payload[0] = 0
        payload[1] = (conid and 0xff).toByte()
        payload[2] = ((conid shr 8) and 0xff).toByte()
        System.arraycopy(remoteIp.address, 0, payload, 3, 4)
        payload[7] = (remotePort and 0xff).toByte()
        payload[8] = ((remotePort shr 8) and 0xff).toByte()
        payload[9] = (data.size and 0xff).toByte()
        payload[10] = ((data.size shr 8) and 0xff).toByte()
        System.arraycopy(data, 0, payload, 11, data.size)
        return try {
            synchronized(writeLock) {
                output.write(payload.size and 0xff)
                output.write((payload.size shr 8) and 0xff)
                output.write(payload)
                output.flush()
            }
            true
        } catch (e: Exception) { false }
    }

    private fun sendKeepalive() {
        try {
            synchronized(writeLock) {
                output.write(3); output.write(0)
                output.write(byteArrayOf(0x01, 0x00, 0x00))
                output.flush()
            }
        } catch (e: Exception) { running.set(false) }
    }

    private fun readLoop() {
        val lenBuf = ByteArray(2)
        try {
            while (running.get()) {
                if (!readFully(lenBuf)) break
                val len = (lenBuf[0].toInt() and 0xff) or ((lenBuf[1].toInt() and 0xff) shl 8)
                if (len < 3 || len > 65535) break
                val pkt = ByteArray(len)
                if (!readFully(pkt)) break
                val flags = pkt[0].toInt() and 0xff
                if (flags and 0x01 != 0) continue
                if (pkt.size < 9) continue
                val conid = (pkt[1].toInt() and 0xff) or ((pkt[2].toInt() and 0xff) shl 8)
                val local = reverse[conid] ?: continue
                val ip = InetAddress.getByAddress(byteArrayOf(pkt[3], pkt[4], pkt[5], pkt[6]))
                val port = (pkt[7].toInt() and 0xff) or ((pkt[8].toInt() and 0xff) shl 8)
                val data = pkt.copyOfRange(9, pkt.size)
                if (data.isEmpty()) continue
                listener?.onPacket(local.first, local.second, ip, port, data)
            }
        } catch (e: Exception) {
            if (running.get()) listener?.onError(e.message ?: "udpgw read error")
        }
        running.set(false)
    }

    private fun readFully(b: ByteArray): Boolean {
        var off = 0
        while (off < b.size) {
            val n = input.read(b, off, b.size - off)
            if (n < 0) return false
            off += n
        }
        return true
    }
}
