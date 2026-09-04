package com.bourass.fastdns

import android.net.VpnService
import android.util.Log
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * FastDNS Tunnel Engine with auto-reconnect and VpnService socket protection.
 *
 * Direct match to FaizVPN pcap architecture:
 *   - Single multiplexed TCP stream on 105.73.34.106:53.
 *   - Transparent socket auto-reconnect on EOF / RST.
 *   - Sockets protected from VPN loopback via VpnService.protect().
 */
class FastDnsEngine(
    private val vpnService: VpnService,
    private val resolverIp: String = "105.73.34.106",
    private val resolverPort: Int = 53,
    private val zone: String = "dns3.marocdns.uk",
    private val subId: String = FastDnsCrypto.DEFAULT_SUB_ID,
    private val installId: String = FastDnsCrypto.DEFAULT_INSTALL_ID
) {
    companion object {
        private const val TAG = "FastDnsEngine"
        val RESOLVER_TARGETS = listOf("105.73.34.106", "105.73.34.105", "213.160.77.162")
    }

    // Cryptographic keys
    private lateinit var subKey: ByteArray
    private lateinit var hsKey: ByteArray
    private var sessionKey: ByteArray? = null

    // Session state
    var sessionHex: String = ""
        private set
    var shortSess: String = "39928"
        private set
    var assignedIp: String = "10.8.135.170"
        private set

    private var uplinkSeq = AtomicInteger((1..1000).random())
    private var pollSeq = AtomicInteger(0)

    // Socket state
    private var activeSocket: Socket? = null
    private var socketOut: OutputStream? = null
    private var socketIn: InputStream? = null
    private val socketLock = Any()
    private var currentTargetIndex = 0

    // Lifecycle state
    val isConnected = AtomicBoolean(false)
    val bytesSent = AtomicLong(0)
    val bytesReceived = AtomicLong(0)

    // Callbacks
    var onDownlinkPacket: ((ByteArray) -> Unit)? = null
    var onStatusChange: ((String) -> Unit)? = null
    var onError: ((String) -> Unit)? = null

    private val running = AtomicBoolean(false)

    fun connect() {
        if (isConnected.get()) return
        running.set(true)

        Thread(Runnable {
            try {
                performConnect()
            } catch (e: Exception) {
                Log.e(TAG, "Connect failed", e)
                onError?.invoke("Connection failed: ${e.message}")
                disconnect()
            }
        }, "FastDNS-Connect").start()
    }

    fun disconnect() {
        running.set(false)
        isConnected.set(false)

        closeSocket()
        onStatusChange?.invoke("Disconnected")
    }

    private fun closeSocket() {
        synchronized(socketLock) {
            try { activeSocket?.close() } catch (_: Exception) {}
            activeSocket = null
            socketOut = null
            socketIn = null
        }
    }

    private fun performConnect() {
        onStatusChange?.invoke("Deriving cryptographic keys...")

        subKey = FastDnsCrypto.deriveSubKey(subId)
        hsKey = FastDnsCrypto.deriveHandshakeKey(subKey, installId)

        val sBytes = ByteArray(16)
        SecureRandom().nextBytes(sBytes)
        sessionHex = FastDnsCrypto.bytesToHex(sBytes)

        shortSess = try {
            Integer.parseInt(sessionHex.substring(0, 4), 16).toString()
        } catch (e: Exception) {
            "39928"
        }

        val octet3 = (10..240).random()
        val octet4 = (10..240).random()
        assignedIp = "10.8.$octet3.$octet4"

        sessionKey = FastDnsCrypto.deriveSessionKey(subKey, installId, sessionHex)

        Log.i(TAG, "Session initialized: sid=$sessionHex, shortSess=$shortSess, assignedIp=$assignedIp")

        // Connect initial socket
        if (!ensureConnected()) {
            onError?.invoke("Could not reach DNS server")
            disconnect()
            return
        }

        isConnected.set(true)
        onStatusChange?.invoke("FastDNS Connected ✓ ($assignedIp)")
        Log.i(TAG, "FastDNS tunnel is ACTIVE")

        // Start downlink poll loop
        Thread(Runnable { pollLoop() }, "FastDNS-Poll").start()
    }

    /**
     * Ensures the TCP socket is connected and protected from VPN routing.
     * Automatically reconnects and rotates servers on connection drops.
     */
    private fun ensureConnected(): Boolean {
        synchronized(socketLock) {
            if (activeSocket != null && activeSocket!!.isConnected && !activeSocket!!.isClosed) {
                return true
            }

            closeSocket()

            val targets = RESOLVER_TARGETS
            for (i in targets.indices) {
                val idx = (currentTargetIndex + i) % targets.size
                val target = targets[idx]

                try {
                    Log.i(TAG, "Connecting TCP socket to $target:$resolverPort")
                    val s = Socket()
                    s.tcpNoDelay = true
                    s.soTimeout = 10000

                    // Protect socket from VPN routing before connecting
                    vpnService.protect(s)

                    s.connect(InetSocketAddress(target, resolverPort), 5000)

                    activeSocket = s
                    socketOut = BufferedOutputStream(s.getOutputStream(), 16384)
                    socketIn = BufferedInputStream(s.getInputStream(), 32768)
                    currentTargetIndex = idx
                    Log.i(TAG, "Socket connected and protected for $target:$resolverPort")
                    return true
                } catch (e: Exception) {
                    Log.w(TAG, "Connect to $target failed: ${e.message}")
                }
            }

            return false
        }
    }

    /**
     * Send uplink IP packet through FastDNS tunnel.
     */
    fun sendUplink(data: ByteArray) {
        if (!isConnected.get() || sessionKey == null) return

        try {
            val seq = uplinkSeq.getAndIncrement()

            // Header: [seq u16 BE] [streamId u8] [data]
            val frame = ByteBuffer.allocate(3 + data.size)
            frame.putShort(seq.toShort())
            frame.put(0x01)
            frame.put(data)
            frame.flip()
            val frameBytes = ByteArray(frame.remaining())
            frame.get(frameBytes)

            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)
            val encrypted = FastDnsCrypto.aesGcmEncrypt(sessionKey!!, nonce, frameBytes)
            val payload = byteArrayOf(0xF1.toByte()) + nonce + encrypted

            val b32 = FastDnsCrypto.base32Encode(payload)
            val labels = FastDnsCrypto.splitIntoLabels(b32, 60)

            val qname = "0-${labels.joinToString(".")}.s$sessionHex.$zone"

            synchronized(socketLock) {
                if (ensureConnected() && socketOut != null) {
                    sendDnsQueryNoWait(socketOut!!, qname)
                    bytesSent.addAndGet(data.size.toLong())
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Uplink send error: ${e.message}")
            closeSocket() // Force reconnect on next send
        }
    }

    /**
     * Downlink polling loop.
     */
    private fun pollLoop() {
        Log.i(TAG, "Poll loop started for shortSess=$shortSess, ip=$assignedIp")

        while (running.get() && isConnected.get()) {
            try {
                val pSeq = pollSeq.getAndIncrement()
                val rand = (100000..999999).random()

                val qname = "0-poll.$shortSess.$pSeq.$rand.s$assignedIp.$zone"

                var response: ByteArray? = null
                synchronized(socketLock) {
                    if (ensureConnected() && socketOut != null && socketIn != null) {
                        response = sendDnsQuery(socketOut!!, socketIn!!, qname)
                    }
                }

                if (response != null && response.isNotEmpty()) {
                    processDownlink(response!!)
                }

                Thread.sleep(80)
            } catch (e: Exception) {
                if (running.get()) {
                    Log.w(TAG, "Poll notice: ${e.message} — reconnecting socket")
                    closeSocket()
                    Thread.sleep(300)
                }
            }
        }

        Log.i(TAG, "Poll loop exited")
    }

    private fun processDownlink(data: ByteArray) {
        if (data.size <= 4) return
        val text = String(data, Charsets.UTF_8)
        if (text == "ok") return
        if (text == "gone") return

        var payload = data
        if (payload.size > 2 && (payload[0].toInt() and 0xFF) == 0xF1) {
            payload = payload.copyOfRange(1, payload.size)
        }

        if (payload.size > 28 && sessionKey != null) {
            try {
                val nonce = payload.copyOfRange(0, 12)
                val ct = payload.copyOfRange(12, payload.size)
                val plain = FastDnsCrypto.aesGcmDecrypt(sessionKey!!, nonce, ct)

                if (plain.size > 3) {
                    val ipPacket = plain.copyOfRange(3, plain.size)
                    bytesReceived.addAndGet(ipPacket.size.toLong())
                    onDownlinkPacket?.invoke(ipPacket)
                }
            } catch (e: Exception) {
                bytesReceived.addAndGet(payload.size.toLong())
                onDownlinkPacket?.invoke(payload)
            }
        } else {
            bytesReceived.addAndGet(payload.size.toLong())
            onDownlinkPacket?.invoke(payload)
        }
    }

    // ---- DNS Wire Protocol Helpers ----

    private fun sendDnsQuery(out: OutputStream, inp: InputStream, qname: String): ByteArray? {
        val txId = (0..0xFFFF).random()
        val packet = buildDnsPacket(txId, qname)

        val lenBuf = ByteBuffer.allocate(2)
        lenBuf.putShort(packet.size.toShort())

        out.write(lenBuf.array())
        out.write(packet)
        out.flush()

        return readDnsResponse(inp)
    }

    private fun sendDnsQueryNoWait(out: OutputStream, qname: String) {
        val txId = (0..0xFFFF).random()
        val packet = buildDnsPacket(txId, qname)
        val lenBuf = ByteBuffer.allocate(2)
        lenBuf.putShort(packet.size.toShort())
        out.write(lenBuf.array())
        out.write(packet)
        out.flush()
    }

    private fun buildDnsPacket(txId: Int, qname: String): ByteArray {
        val buf = ByteArrayOutputStream()

        buf.write(byteArrayOf((txId shr 8).toByte(), (txId and 0xFF).toByte()))
        buf.write(byteArrayOf(0x01, 0x00))
        buf.write(byteArrayOf(0x00, 0x01))
        buf.write(byteArrayOf(0x00, 0x00))
        buf.write(byteArrayOf(0x00, 0x00))
        buf.write(byteArrayOf(0x00, 0x00))

        for (label in qname.trimEnd('.').split(".")) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            buf.write(bytes.size)
            buf.write(bytes)
        }
        buf.write(0x00)

        buf.write(byteArrayOf(0x00, 0x0A)) // QTYPE 10 (NULL)
        buf.write(byteArrayOf(0x00, 0x01)) // QCLASS 1 (IN)

        return buf.toByteArray()
    }

    private fun readDnsResponse(inp: InputStream): ByteArray? {
        val lenBytes = ByteArray(2)
        var read = 0
        while (read < 2) {
            val r = inp.read(lenBytes, read, 2 - read)
            if (r <= 0) return null
            read += r
        }
        val responseLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (responseLen < 12 || responseLen > 65535) return null

        val response = ByteArray(responseLen)
        read = 0
        while (read < responseLen) {
            val r = inp.read(response, read, responseLen - read)
            if (r <= 0) return null
            read += r
        }

        return extractRdata(response)
    }

    private fun extractRdata(response: ByteArray): ByteArray? {
        if (response.size < 12) return null

        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (anCount == 0) return null

        var offset = 12
        val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        for (i in 0 until qdCount) {
            offset = skipDnsName(response, offset)
            offset += 4
        }

        if (offset >= response.size) return null
        offset = skipDnsName(response, offset)
        if (offset + 10 > response.size) return null

        offset += 2 // TYPE
        offset += 2 // CLASS
        offset += 4 // TTL

        val rdLength = ((response[offset].toInt() and 0xFF) shl 8) or (response[offset + 1].toInt() and 0xFF)
        offset += 2

        if (offset + rdLength > response.size) return null
        return response.copyOfRange(offset, offset + rdLength)
    }

    private fun skipDnsName(data: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        while (offset < data.size) {
            val len = data[offset].toInt() and 0xFF
            if (len == 0) {
                offset++
                break
            }
            if ((len and 0xC0) == 0xC0) {
                offset += 2
                break
            }
            offset += 1 + len
        }
        return offset
    }

    fun getSocket(): Socket? = activeSocket
}
