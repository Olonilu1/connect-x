package com.jayboy.vpn
import java.net.InetAddress
import java.nio.ByteBuffer

data class IPv4Header(
    val version: Int,
    val ihl: Int,
    val totalLength: Int,
    val identification: Int,
    val flags: Int,
    val fragmentOffset: Int,
    val ttl: Int,
    val protocol: Byte,
    var headerChecksum: Int,
    val sourceIp: InetAddress,
    val destinationIp: InetAddress,
    val payload: ByteArray
) {
    companion object {
        fun parse(data: ByteArray): IPv4Header? {
            if (data.size < 20) return null
            val buffer = ByteBuffer.wrap(data)
            
            val versionAndIhl = buffer.get().toInt()
            val version = versionAndIhl shr 4
            val ihl = versionAndIhl and 0x0F
            if (ihl < 5) return null

            buffer.get() // DSCP & ECN
            val totalLength = buffer.short.toInt() and 0xFFFF
            val identification = buffer.short.toInt() and 0xFFFF
            val flagsAndFragment = buffer.short.toInt() and 0xFFFF
            val flags = flagsAndFragment shr 13
            val fragmentOffset = flagsAndFragment and 0x1FFF
            val ttl = buffer.get().toInt() and 0xFF
            val protocol = buffer.get()
            val headerChecksum = buffer.short.toInt() and 0xFFFF

            val sourceIpBytes = ByteArray(4)
            buffer.get(sourceIpBytes)
            val sourceIp = InetAddress.getByAddress(sourceIpBytes)

            val destIpBytes = ByteArray(4)
            buffer.get(destIpBytes)
            val destinationIp = InetAddress.getByAddress(destIpBytes)
            
            val payload = data.copyOfRange(ihl * 4, totalLength)

            return IPv4Header(
                version, ihl, totalLength, identification, flags,
                fragmentOffset, ttl, protocol, headerChecksum, sourceIp, destinationIp, payload
            )
        }
    }
    
    fun buildPacket(tcpHeader: TCPHeader): ByteArray {
         val ipHeaderBytes = toByteArray()
         val tcpHeaderBytes = tcpHeader.toByteArray(sourceIp, destinationIp)
         return ipHeaderBytes + tcpHeaderBytes
    }

    fun toByteArrayForUdp(): ByteArray {
        val ipHeaderSize = ihl * 4
        val buffer = ByteBuffer.allocate(ipHeaderSize)
        buffer.put(((version shl 4) or ihl).toByte())
        buffer.put(0) // DSCP & ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(identification.toShort())
        buffer.putShort(((flags shl 13) or fragmentOffset).toShort())
        buffer.put(ttl.toByte())
        buffer.put(protocol)
        buffer.putShort(0) // Checksum placeholder
        buffer.put(sourceIp.address)
        buffer.put(destinationIp.address)

        // Calculate IP header checksum
        val array = buffer.array()
        val checksum = calculateChecksum(array, 0, ipHeaderSize)
        buffer.putShort(10, checksum.toShort())

        return array + payload
    }

    private fun toByteArray(): ByteArray {
        val buffer = ByteBuffer.allocate(ihl * 4)
        buffer.put(((version shl 4) or ihl).toByte())
        buffer.put(0) // DSCP & ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(identification.toShort())
        buffer.putShort(((flags shl 13) or fragmentOffset).toShort())
        buffer.put(ttl.toByte())
        buffer.put(protocol)
        buffer.putShort(0) // Checksum placeholder

        buffer.put(sourceIp.address)
        buffer.put(destinationIp.address)

        // Calculate checksum
        val array = buffer.array()
        val checksum = calculateChecksum(array, 0, buffer.position())
        buffer.putShort(10, checksum.toShort())

        return array
    }
}

data class TCPHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgmentNumber: Long,
    val dataOffset: Int,
    val flags: Int,
    val windowSize: Int,
    var checksum: Int,
    val urgentPointer: Int,
    val payload: ByteArray
) {
    companion object {
        const val FLAG_FIN = 1
        const val FLAG_SYN = 2
        const val FLAG_RST = 4
        const val FLAG_PSH = 8
        const val FLAG_ACK = 16
        const val FLAG_URG = 32

        fun parse(data: ByteArray): TCPHeader? {
            if (data.size < 20) return null
            val buffer = ByteBuffer.wrap(data)

            val sourcePort = buffer.short.toInt() and 0xFFFF
            val destinationPort = buffer.short.toInt() and 0xFFFF
            val sequenceNumber = buffer.int.toLong() and 0xFFFFFFFF
            val acknowledgmentNumber = buffer.int.toLong() and 0xFFFFFFFF
            val dataOffsetAndFlags = buffer.short.toInt() and 0xFFFF
            val dataOffset = (dataOffsetAndFlags shr 12) and 0xF
            val flags = dataOffsetAndFlags and 0x1FF
            val windowSize = buffer.short.toInt() and 0xFFFF
            val checksum = buffer.short.toInt() and 0xFFFF
            val urgentPointer = buffer.short.toInt() and 0xFFFF

            val payload = data.copyOfRange(dataOffset * 4, data.size)

            return TCPHeader(
                sourcePort, destinationPort, sequenceNumber, acknowledgmentNumber,
                dataOffset, flags, windowSize, checksum, urgentPointer, payload
            )
        }
    }
    
    val isFIN: Boolean get() = (flags and FLAG_FIN) != 0
    val isSYN: Boolean get() = (flags and FLAG_SYN) != 0
    val isRST: Boolean get() = (flags and FLAG_RST) != 0
    val isACK: Boolean get() = (flags and FLAG_ACK) != 0

    fun toByteArray(sourceIp: InetAddress, destIp: InetAddress): ByteArray {
        val tcpLength = (dataOffset * 4) + payload.size
        val buffer = ByteBuffer.allocate(tcpLength)

        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putInt(sequenceNumber.toInt())
        buffer.putInt(acknowledgmentNumber.toInt())
        buffer.putShort(((dataOffset shl 12) or flags).toShort())
        buffer.putShort(windowSize.toShort())
        buffer.putShort(0) // Checksum placeholder
        buffer.putShort(urgentPointer.toShort())
        buffer.put(payload)

        // Calculate checksum
        val array = buffer.array()
        val pseudoHeader = createPseudoHeader(sourceIp, destIp, tcpLength)
        val checksum = calculateChecksum(pseudoHeader + array, 0, pseudoHeader.size + array.size)
        buffer.putShort(16, checksum.toShort())

        return array
    }
    
     private fun createPseudoHeader(sourceIp: InetAddress, destIp: InetAddress, tcpLength: Int): ByteArray {
        val buffer = ByteBuffer.allocate(12)
        buffer.put(sourceIp.address)
        buffer.put(destIp.address)
        buffer.put(0.toByte())
        buffer.put(6.toByte()) // Protocol TCP
        buffer.putShort(tcpLength.toShort())
        return buffer.array()
    }
}

fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var i = offset
    while (i < length - 1) {
        val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
        sum += word
        i += 2
    }
    if (length % 2 != 0) {
        sum += (data[length - 1].toInt() and 0xFF) shl 8
    }
    while (sum shr 16 > 0) {
        sum = (sum and 0xFFFF) + (sum shr 16)
    }
    return sum.inv() and 0xFFFF
}

data class UDPHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val length: Int,
    var checksum: Int,
    val payload: ByteArray
) {
    companion object {
        fun parse(data: ByteArray): UDPHeader? {
            if (data.size < 8) return null
            val buffer = ByteBuffer.wrap(data)

            val sourcePort = buffer.short.toInt() and 0xFFFF
            val destinationPort = buffer.short.toInt() and 0xFFFF
            val length = buffer.short.toInt() and 0xFFFF
            val checksum = buffer.short.toInt() and 0xFFFF

            val payload = if (data.size > 8) data.copyOfRange(8, minOf(length, data.size)) else ByteArray(0)

            return UDPHeader(sourcePort, destinationPort, length, checksum, payload)
        }
    }

    fun toByteArray(sourceIp: InetAddress, destIp: InetAddress): ByteArray {
        val buffer = ByteBuffer.allocate(8 + payload.size)
        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putShort((8 + payload.size).toShort())
        buffer.putShort(0) // Checksum placeholder
        buffer.put(payload)

        // Calculate UDP checksum with pseudo-header
        val array = buffer.array()
        val pseudoHeader = createUdpPseudoHeader(sourceIp, destIp, 8 + payload.size)
        val checksum = calculateChecksum(pseudoHeader + array, 0, pseudoHeader.size + array.size)
        buffer.putShort(6, checksum.toShort())

        return array
    }

    private fun createUdpPseudoHeader(sourceIp: InetAddress, destIp: InetAddress, udpLength: Int): ByteArray {
        val buffer = ByteBuffer.allocate(12)
        buffer.put(sourceIp.address)
        buffer.put(destIp.address)
        buffer.put(0.toByte())
        buffer.put(17.toByte()) // Protocol UDP
        buffer.putShort(udpLength.toShort())
        return buffer.array()
    }
}