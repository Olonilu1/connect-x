package com.connectx.vpn

import java.io.InputStream

interface Transport {
    fun connect(): Boolean
    fun send(payload: ByteArray)
    val inputStream: InputStream?
    val outputStream: java.io.OutputStream?
    var onDataReceived: ((ByteArray) -> Unit)?
    fun disconnect()
}
