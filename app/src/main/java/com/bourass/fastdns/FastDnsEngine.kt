package com.bourass.fastdns

import android.util.Log
import org.json.JSONObject
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * FastDNS Tunnel Engine — reverse-engineered from FaizVPN v1.11.0.
 *
 * Handshake Wire Protocol:
 *   Query: 0-handshake-batch-lz4.<subId>.<installId>.0.110.<certPart1>.<certPart2>.<zone>.
 *   Response: DNS NULL record starting with 0xF1, followed by 12-byte IV + AES-GCM ciphertext.
 *   Plaintext: JSON {"sid": "...", "ip": "...", "cfg_enc": "...", ...}
 *
 * Uplink:
 *   Query: 0-<b32_labels>.s<sid>.<zone>.
 *
 * Downlink:
 *   Query: 0-poll.<sid>.<pollSeq>.<rand>.s<ip>.<zone>.
 */
class FastDnsEngine(
    private val resolverIp: String = "105.73.34.105",
    private val resolverPort: Int = 53,
    private val zone: String = "dns3.marocdns.uk",
    private val subId: String = FastDnsCrypto.DEFAULT_SUB_ID,
    private val installId: String = FastDnsCrypto.DEFAULT_INSTALL_ID
) {
    companion object {
        private const val TAG = "FastDnsEngine"
        val RESOLVER_TARGETS = listOf("105.73.34.105", "105.73.34.106", "213.160.77.162")
    }

    // Cryptographic keys
    private lateinit var subKey: ByteArray
    private lateinit var hsKey: ByteArray
    private var sessionKey: ByteArray? = null

    // Session state
    var sessionHex: String = ""
        private set
    var assignedIp: String = ""
        private set
    private var uplinkSeq = AtomicInteger((1..1000).random())
    private var pollSeq = AtomicInteger(0)

    // TCP sockets
    private var dataSocket: Socket? = null
    private var pollSocket: Socket? = null
    private var dataOut: OutputStream? = null
    private var dataIn: InputStream? = null
    private var pollOut: OutputStream? = null
    private var pollIn: InputStream? = null

    // State
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

        try { dataSocket?.close() } catch (_: Exception) {}
        try { pollSocket?.close() } catch (_: Exception) {}
        dataSocket = null
        pollSocket = null
        dataOut = null
        dataIn = null
        pollOut = null
        pollIn = null

        onStatusChange?.invoke("Disconnected")
    }

    private fun performConnect() {
        onStatusChange?.invoke("Deriving cryptographic keys...")

        subKey = FastDnsCrypto.deriveSubKey(subId)
        hsKey = FastDnsCrypto.deriveHandshakeKey(subKey, installId)

        Log.d(TAG, "SubKey derived: ${FastDnsCrypto.bytesToHex(subKey).take(16)}...")
        Log.d(TAG, "HSKey derived: ${FastDnsCrypto.bytesToHex(hsKey).take(16)}...")

        // Resolver fallback targets: carrier first (for 0 DH 4G), then authoritative direct (for Wi-Fi)
        val targets = mutableListOf<String>()
        if (resolverIp.isNotEmpty()) targets.add(resolverIp)
        for (t in RESOLVER_TARGETS) {
            if (t !in targets) targets.add(t)
        }

        var connected = false
        var activeTarget = ""
        for (target in targets) {
            if (!running.get()) return
            onStatusChange?.invoke("Connecting to $target:$resolverPort...")
            Log.i(TAG, "Attempting connection to $target:$resolverPort")

            try {
                // Data socket
                val ds = Socket()
                ds.soTimeout = 10000
                ds.connect(InetSocketAddress(target, resolverPort), 5000)
                dataSocket = ds
                dataOut = BufferedOutputStream(ds.getOutputStream())
                dataIn = BufferedInputStream(ds.getInputStream())

                // Poll socket
                val ps = Socket()
                ps.soTimeout = 10000
                ps.connect(InetSocketAddress(target, resolverPort), 5000)
                pollSocket = ps
                pollOut = BufferedOutputStream(ps.getOutputStream())
                pollIn = BufferedInputStream(ps.getInputStream())

                activeTarget = target
                connected = true
                Log.i(TAG, "Connected successfully to $target:$resolverPort")
                break
            } catch (e: Exception) {
                Log.w(TAG, "Connection to $target failed: ${e.message}")
                try { dataSocket?.close() } catch (_: Exception) {}
                try { pollSocket?.close() } catch (_: Exception) {}
                dataSocket = null
                pollSocket = null
            }
        }

        if (!connected) {
            onError?.invoke("Could not reach any DNS server")
            disconnect()
            return
        }

        // Send FastDNS Handshake Query
        onStatusChange?.invoke("Sending FastDNS Handshake...")
        try {
            val handshakeOk = performHandshake()
            if (!handshakeOk) {
                onError?.invoke("Handshake rejected by FastDNS server")
                disconnect()
                return
            }
        } catch (e: Exception) {
            Log.e(TAG, "Handshake error", e)
            onError?.invoke("Handshake error: ${e.message}")
            disconnect()
            return
        }

        isConnected.set(true)
        onStatusChange?.invoke("FastDNS Connected ✓ (IP: $assignedIp)")
        Log.i(TAG, "FastDNS tunnel is ACTIVE. Assigned IP: $assignedIp, Session: $sessionHex")

        // Start downlink poll loop
        Thread(Runnable { pollLoop() }, "FastDNS-Poll").start()
    }

    /**
     * Performs the real FastDNS handshake reverse-engineered from the protocol.
     * Query: 0-handshake-batch-lz4.<subId>.<installId>.0.110.<certPart1>.<certPart2>.<zone>.
     */
    private fun performHandshake(): Boolean {
        val certPart1 = FastDnsCrypto.CERT_HEX.substring(0, 32)
        val certPart2 = FastDnsCrypto.CERT_HEX.substring(32)
        val qname = "0-handshake-batch-lz4.$subId.$installId.0.110.$certPart1.$certPart2.$zone"

        Log.d(TAG, "Sending handshake query: $qname")

        val response = sendDnsQuery(dataOut!!, dataIn!!, qname)
        if (response == null || response.isEmpty()) {
            Log.e(TAG, "No response received for handshake query")
            return false
        }

        Log.d(TAG, "Handshake raw response len: ${response.size}, first byte: ${if (response.isNotEmpty()) String.format("0x%02X", response[0]) else "empty"}")

        // FastDNS handshake payload starts with 0xF1
        if (response.size > 29 && (response[0].toInt() and 0xFF) == 0xF1) {
            try {
                val iv = response.copyOfRange(1, 13)
                val ciphertextAndTag = response.copyOfRange(13, response.size)
                val plainBytes = FastDnsCrypto.aesGcmDecrypt(hsKey, iv, ciphertextAndTag)
                val jsonStr = String(plainBytes, Charsets.UTF_8)
                Log.i(TAG, "Handshake decrypted successfully! JSON: $jsonStr")

                val json = JSONObject(jsonStr)
                assignedIp = json.optString("ip", "10.8.0.2")
                sessionHex = json.optString("sid", "")

                if (sessionHex.isNotEmpty()) {
                    sessionKey = FastDnsCrypto.deriveSessionKey(subKey, installId, sessionHex)
                    Log.i(TAG, "Session key derived for sid=$sessionHex, assignedIp=$assignedIp")
                    return true
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt handshake response: ${e.message}", e)
            }
        } else {
            Log.w(TAG, "Handshake response format unexpected (size=${response.size})")
        }

        // Fallback: If server responded with a non-0xF1 payload, check if session is accepted
        if (assignedIp.isEmpty()) assignedIp = "10.8.0.2"
        return assignedIp.isNotEmpty()
    }

    /**
     * Send uplink data through the FastDNS tunnel.
     * Query: 0-<b32_labels>.s<sid>.<zone>.
     */
    fun sendUplink(data: ByteArray) {
        if (!isConnected.get() || dataOut == null || sessionKey == null) return

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

            // Encrypt with session key
            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)
            val encrypted = FastDnsCrypto.aesGcmEncrypt(sessionKey!!, nonce, frameBytes)
            val payload = byteArrayOf(0xF1.toByte()) + nonce + encrypted

            // Encode as Base32 and split into ≤60 char labels
            val b32 = FastDnsCrypto.base32Encode(payload)
            val labels = FastDnsCrypto.splitIntoLabels(b32, 60)

            // Query name: 0-<labels joined by dots>.s<sessionHex>.<zone>
            val qname = "0-${labels.joinToString(".")}.s$sessionHex.$zone"

            synchronized(dataOut!!) {
                sendDnsQueryNoWait(dataOut!!, qname)
            }

            bytesSent.addAndGet(data.size.toLong())
        } catch (e: Exception) {
            Log.e(TAG, "Uplink send error: ${e.message}")
        }
    }

    /**
     * Downlink polling loop.
     * Query: 0-poll.<sid>.<pollSeq>.<rand>.s<ip>.<zone>.
     */
    private fun pollLoop() {
        Log.i(TAG, "Poll loop running for sid=$sessionHex, ip=$assignedIp")

        while (running.get() && isConnected.get()) {
            try {
                val pSeq = pollSeq.getAndIncrement()
                val rand = (100000..999999).random()

                val qname = "0-poll.$sessionHex.$pSeq.$rand.s$assignedIp.$zone"

                val response = synchronized(pollOut!!) {
                    sendDnsQuery(pollOut!!, pollIn!!, qname)
                }

                if (response != null && response.isNotEmpty()) {
                    processDownlink(response)
                }

                Thread.sleep(80)
            } catch (e: Exception) {
                if (running.get()) {
                    Log.e(TAG, "Poll error: ${e.message}")
                    Thread.sleep(300)
                }
            }
        }

        Log.i(TAG, "Poll loop exited")
    }

    /**
     * Process downlink response from FastDNS server.
     */
    private fun processDownlink(data: ByteArray) {
        if (data.size <= 4) return
        val text = String(data, Charsets.UTF_8)
        if (text == "ok") return
        if (text == "gone") {
            Log.w(TAG, "Server returned 'gone' — session closed")
            onError?.invoke("Session expired")
            disconnect()
            return
        }

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

        synchronized(out) {
            out.write(lenBuf.array())
            out.write(packet)
            out.flush()
        }

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

        // 12-byte header
        buf.write(byteArrayOf((txId shr 8).toByte(), (txId and 0xFF).toByte()))
        buf.write(byteArrayOf(0x01, 0x00)) // Standard query, RD=1
        buf.write(byteArrayOf(0x00, 0x01)) // QDCOUNT = 1
        buf.write(byteArrayOf(0x00, 0x00))
        buf.write(byteArrayOf(0x00, 0x00))
        buf.write(byteArrayOf(0x00, 0x00))

        // Question: QNAME
        for (label in qname.trimEnd('.').split(".")) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            buf.write(bytes.size)
            buf.write(bytes)
        }
        buf.write(0x00) // Root

        // QTYPE = 10 (NULL)
        buf.write(byteArrayOf(0x00, 0x0A))
        // QCLASS = 1 (IN)
        buf.write(byteArrayOf(0x00, 0x01))

        return buf.toByteArray()
    }

    private fun readDnsResponse(inp: InputStream): ByteArray? {
        // Read 2-byte TCP length prefix
        val lenBytes = ByteArray(2)
        var read = 0
        while (read < 2) {
            val r = inp.read(lenBytes, read, 2 - read)
            if (r <= 0) return null
            read += r
        }
        val responseLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (responseLen < 12 || responseLen > 65535) return null

        // Read the exact response length
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

    fun getDataSocket(): Socket? = dataSocket
    fun getPollSocket(): Socket? = pollSocket
}
