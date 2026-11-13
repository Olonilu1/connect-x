package com.jayboy.vpn

import android.util.Log
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream

/** One TCP connection carried over the SSH leg inside the dnstt tunnel. */
class SshConnection(
    private val sessionProvider: () -> Session?,
    private val targetHost: String,
    private val targetPort: Int
) : Transport {

    companion object { private const val TAG = "SshConnection" }

    private var channel: ChannelDirectTCPIP? = null
    private var readerThread: Thread? = null
    private var inStream: InputStream? = null
    private var outStream: OutputStream? = null

    override var onDataReceived: ((ByteArray) -> Unit)? = null
    override val inputStream: InputStream? get() = inStream
    override val outputStream: OutputStream? get() = outStream

    override fun connect(): Boolean {
        val session = sessionProvider() ?: return false
        return try {
            val ch = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(targetHost)
            ch.setPort(targetPort)
            inStream = ch.inputStream
            outStream = ch.outputStream
            ch.connect(15000)
            channel = ch
            readerThread = Thread { readLoop() }.also { it.start() }
            Log.d(TAG, "ssh channel up: $targetHost:$targetPort")
            true
        } catch (e: Exception) {
            Log.e(TAG, "ssh channel failed: $targetHost:$targetPort", e)
            disconnect()
            false
        }
    }

    private fun readLoop() {
        val input = inStream ?: return
        val buf = ByteArray(16384)
        try {
            while (true) {
                val n = input.read(buf)
                if (n > 0) onDataReceived?.invoke(buf.copyOf(n))
                else if (n < 0) break
            }
        } catch (_: Exception) {
        }
    }

    override fun send(payload: ByteArray) {
        try {
            outStream?.write(payload)
            outStream?.flush()
        } catch (e: Exception) {
            Log.e(TAG, "ssh send failed", e)
        }
    }

    override fun disconnect() {
        try { channel?.disconnect() } catch (_: Exception) {}
        try { readerThread?.interrupt() } catch (_: Exception) {}
        channel = null
        inStream = null
        outStream = null
    }
}
