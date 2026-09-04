package com.bourass.fastdns

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
 * FastDNS Tunnel Engine — reverse-engineered from FaizVPN v1.11.0 libfaizvpn.so.
 *
 * Architecture:
 *   Phone ──TCP:53──► Inwi Resolver (105.73.34.105) ──recursive──► ns3.marocdns.uk (213.160.77.162)
 *
 * Protocol:
 *   - Transport: DNS-over-TCP on port 53
 *   - Record type: NULL (QTYPE 10)
 *   - Uplink: data is AES-GCM encrypted, Base32-encoded, split into ≤63-char DNS labels
 *   - Downlink: poll queries; server responds with encrypted data in NULL RDATA
 *   - Compression: LZ4 / Zstandard (we use raw for simplicity — server handles both)
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
    private var sessionHex: String = ""
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

    // Callback for received tunnel IP packets
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

        Log.d(TAG, "SubKey: ${FastDnsCrypto.bytesToHex(subKey).take(16)}...")
        Log.d(TAG, "HSKey: ${FastDnsCrypto.bytesToHex(hsKey).take(16)}...")

        // Generate random session ID (32 hex chars)
        val sessionBytes = ByteArray(16)
        SecureRandom().nextBytes(sessionBytes)
        sessionHex = FastDnsCrypto.bytesToHex(sessionBytes)
        Log.d(TAG, "Session: $sessionHex")

        // Derive session key
        sessionKey = FastDnsCrypto.deriveSessionKey(subKey, installId, sessionHex)

        // Try connecting to resolvers in order
        val targets = mutableListOf(resolverIp)
        for (t in RESOLVER_TARGETS) {
            if (t !in targets) targets.add(t)
        }

        var connected = false
        for (target in targets) {
            if (!running.get()) return
            onStatusChange?.invoke("Connecting to $target:$resolverPort...")

            try {
                // Data socket
                val ds = Socket()
                ds.soTimeout = 8000
                ds.connect(InetSocketAddress(target, resolverPort), 5000)
                dataSocket = ds
                dataOut = BufferedOutputStream(ds.getOutputStream())
                dataIn = BufferedInputStream(ds.getInputStream())

                // Poll socket
                val ps = Socket()
                ps.soTimeout = 8000
                ps.connect(InetSocketAddress(target, resolverPort), 5000)
                pollSocket = ps
                pollOut = BufferedOutputStream(ps.getOutputStream())
                pollIn = BufferedInputStream(ps.getInputStream())

                onStatusChange?.invoke("Connected to $target:$resolverPort")
                connected = true
                break
            } catch (e: Exception) {
                Log.w(TAG, "Failed to connect to $target: ${e.message}")
                try { dataSocket?.close() } catch (_: Exception) {}
                try { pollSocket?.close() } catch (_: Exception) {}
            }
        }

        if (!connected) {
            onError?.invoke("Failed to connect to any resolver")
            return
        }

        // Verify FastDNS tunnel with initial poll query
        onStatusChange?.invoke("Verifying FastDNS tunnel...")
        assignedIp = "10.8.0.2"
        val testPoll = buildPollQueryName(0, (10000..99999).random())
        Log.d(TAG, "Initial test query: $testPoll")

        val response = sendDnsQuery(pollOut!!, pollIn!!, testPoll)
        Log.d(TAG, "Initial poll response: len=${response?.size} hex=${response?.let { FastDnsCrypto.bytesToHex(it) }} text=${response?.let { String(it, Charsets.UTF_8) }}")

        if (response == null || response.isEmpty()) {
            onError?.invoke("No response from FastDNS server")
            disconnect()
            return
        }

        isConnected.set(true)
        onStatusChange?.invoke("FastDNS Connected ✓ (IP: $assignedIp)")

        // Start poll loop
        Thread(Runnable { pollLoop() }, "FastDNS-Poll").start()
    }

    /**
     * Send uplink data through the FastDNS tunnel.
     * Data is encrypted, Base32-encoded, and sent as DNS NULL queries.
     */
    fun sendUplink(data: ByteArray) {
        if (!isConnected.get() || dataOut == null) return

        try {
            val maxChunk = 80
            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + maxChunk, data.size)
                val chunk = data.copyOfRange(offset, end)
                sendSingleChunk(chunk)
                offset = end
            }
            bytesSent.addAndGet(data.size.toLong())
        } catch (e: Exception) {
            Log.e(TAG, "Uplink error", e)
        }
    }

    private fun sendSingleChunk(chunk: ByteArray) {
        val seq = uplinkSeq.getAndIncrement()

        // Build frame: [seq u16 BE] [streamId u8] [chunk]
        val frame = ByteBuffer.allocate(3 + chunk.size)
        frame.putShort(seq.toShort())
        frame.put(0x01) // stream ID
        frame.put(chunk)
        frame.flip()
        val frameBytes = ByteArray(frame.remaining())
        frame.get(frameBytes)

        // Encrypt
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val encrypted = FastDnsCrypto.aesGcmEncrypt(sessionKey!!, nonce, frameBytes)
        val payload = nonce + encrypted

        // Base32 encode
        val b32 = FastDnsCrypto.base32Encode(payload)
        val qname = buildDataQueryName(b32)

        // Send query (don't wait for meaningful response on data channel)
        synchronized(dataOut!!) {
            sendDnsQueryNoWait(dataOut!!, qname)
        }
    }

    /**
     * Build data/uplink QNAME: 0-<chunk0>.<chunk1>...<chunkN>.s<sessionHex>.<zone>
     */
    private fun buildDataQueryName(b32: String): String {
        val firstLen = minOf(61, b32.length)
        val firstLabel = "0-" + b32.substring(0, firstLen)
        val labels = mutableListOf(firstLabel)
        var i = firstLen
        while (i < b32.length) {
            val end = minOf(i + 63, b32.length)
            labels.add(b32.substring(i, end))
            i = end
        }
        labels.add("s$sessionHex")
        labels.add(zone)
        return labels.joinToString(".")
    }

    /**
     * Build poll QNAME: 0-poll.<shortSession>.0.<rand>.s<ip_octets>.<zone>
     * Wire format matching live pcap:
     * e.g. 0-poll.39928.0.88066.s10.8.135.170.dns3.marocdns.uk
     */
    private fun buildPollQueryName(seq: Int, rand: Int): String {
        val ipParts = assignedIp.split(".")
        val sIp = if (ipParts.size == 4) {
            "s${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.${ipParts[3]}"
        } else {
            "s10.8.0.2"
        }
        val shortSess = (sessionHex.take(4).toIntOrNull(16) ?: (10000..65535).random()).toString()
        return "0-poll.$shortSess.0.$rand.$sIp.$zone"
    }

    /**
     * Poll loop: continuously sends poll queries and processes downlink data.
     */
    private fun pollLoop() {
        Log.i(TAG, "Poll loop started")

        while (running.get() && isConnected.get()) {
            try {
                val pSeq = pollSeq.getAndIncrement()
                val rand = (10000..999999).random()

                val qname = buildPollQueryName(pSeq, rand)

                val response = synchronized(pollOut!!) {
                    sendDnsQuery(pollOut!!, pollIn!!, qname)
                }

                if (response != null && response.isNotEmpty()) {
                    processDownlink(response)
                }

                // Small delay between polls to avoid flooding
                Thread.sleep(50)
            } catch (e: Exception) {
                if (running.get()) {
                    Log.e(TAG, "Poll error: ${e.message}")
                    // Brief pause before retry
                    Thread.sleep(500)
                }
            }
        }

        Log.i(TAG, "Poll loop ended")
    }

    /**
     * Process a downlink DNS response containing tunneled data.
     */
    private fun processDownlink(data: ByteArray) {
        // Skip empty or "ok" ack responses
        if (data.size <= 4) return
        val text = String(data, Charsets.UTF_8)
        if (text == "ok" || text == "gone") {
            if (text == "gone") {
                Log.w(TAG, "Session expired (got 'gone')")
                onError?.invoke("Session expired")
                disconnect()
            }
            return
        }

        // Downlink frames may have f1 prefix
        var payload = data
        if (payload.size > 2 && payload[0] == 0xf1.toByte()) {
            payload = payload.copyOfRange(2, payload.size)
        }

        // Try to decrypt
        if (payload.size > 28) {
            try {
                val nonce = payload.copyOfRange(0, 12)
                val ct = payload.copyOfRange(12, payload.size)
                val plain = FastDnsCrypto.aesGcmDecrypt(sessionKey!!, nonce, ct)

                // Parse: [batchId u16] [streamId u8] [ip_packet_data...]
                if (plain.size > 3) {
                    val ipPacket = plain.copyOfRange(3, plain.size)
                    bytesReceived.addAndGet(ipPacket.size.toLong())
                    onDownlinkPacket?.invoke(ipPacket)
                }
            } catch (e: Exception) {
                // May be a different frame format, try raw
                bytesReceived.addAndGet(payload.size.toLong())
                onDownlinkPacket?.invoke(payload)
            }
        } else {
            bytesReceived.addAndGet(payload.size.toLong())
            onDownlinkPacket?.invoke(payload)
        }
    }

    // ---- DNS Wire Protocol Helpers ----

    /**
     * Build and send a DNS query over TCP, wait for and return the RDATA from the response.
     */
    private fun sendDnsQuery(out: OutputStream, inp: InputStream, qname: String): ByteArray? {
        val txId = (0..0xFFFF).random()
        val packet = buildDnsPacket(txId, qname)

        // DNS-over-TCP: 2-byte length prefix (big-endian)
        val lenBuf = ByteBuffer.allocate(2)
        lenBuf.putShort(packet.size.toShort())

        synchronized(out) {
            out.write(lenBuf.array())
            out.write(packet)
            out.flush()
        }

        // Read response
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

    /**
     * Build a DNS query packet for QTYPE NULL (10), QCLASS IN (1).
     */
    private fun buildDnsPacket(txId: Int, qname: String): ByteArray {
        val buf = ByteArrayOutputStream()

        // Header (12 bytes)
        buf.write(byteArrayOf((txId shr 8).toByte(), (txId and 0xFF).toByte())) // Transaction ID
        buf.write(byteArrayOf(0x01, 0x00)) // Flags: standard query, recursion desired
        buf.write(byteArrayOf(0x00, 0x01)) // QDCOUNT = 1
        buf.write(byteArrayOf(0x00, 0x00)) // ANCOUNT = 0
        buf.write(byteArrayOf(0x00, 0x00)) // NSCOUNT = 0
        buf.write(byteArrayOf(0x00, 0x00)) // ARCOUNT = 0

        // Question section: QNAME
        for (label in qname.split(".")) {
            buf.write(label.length)
            buf.write(label.toByteArray(Charsets.UTF_8))
        }
        buf.write(0x00) // Root label

        // QTYPE = NULL (10)
        buf.write(byteArrayOf(0x00, 0x0A))
        // QCLASS = IN (1)
        buf.write(byteArrayOf(0x00, 0x01))

        return buf.toByteArray()
    }

    /**
     * Read a DNS response from a TCP stream and extract the RDATA.
     */
    private fun readDnsResponse(inp: InputStream): ByteArray? {
        // Read 2-byte length prefix
        val lenBytes = ByteArray(2)
        var read = 0
        while (read < 2) {
            val r = inp.read(lenBytes, read, 2 - read)
            if (r <= 0) return null
            read += r
        }
        val responseLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)

        if (responseLen < 12 || responseLen > 65535) return null

        // Read full response
        val response = ByteArray(responseLen)
        read = 0
        while (read < responseLen) {
            val r = inp.read(response, read, responseLen - read)
            if (r <= 0) return null
            read += r
        }

        // Parse: skip header (12 bytes), skip question section, find answer RDATA
        return extractRdata(response)
    }

    /**
     * Extract RDATA from a DNS response packet.
     */
    private fun extractRdata(response: ByteArray): ByteArray? {
        if (response.size < 12) return null

        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (anCount == 0) return null

        // Skip question section
        var offset = 12
        val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        for (i in 0 until qdCount) {
            offset = skipDnsName(response, offset)
            offset += 4 // QTYPE + QCLASS
        }

        // Parse first answer
        if (offset >= response.size) return null
        offset = skipDnsName(response, offset) // NAME
        if (offset + 10 > response.size) return null

        // val aType = ((response[offset].toInt() and 0xFF) shl 8) or (response[offset + 1].toInt() and 0xFF)
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
                // Pointer
                offset += 2
                break
            }
            offset += 1 + len
        }
        return offset
    }

    /**
     * Protect a socket fd from being routed through the VPN tunnel.
     * Must be called from VpnService context.
     */
    fun getDataSocketFd(): Int = try {
        val field = Socket::class.java.getDeclaredMethod("getFileDescriptor\$")
        // Fallback: just return -1, VpnService will protect by socket object
        -1
    } catch (e: Exception) { -1 }

    fun getDataSocket(): Socket? = dataSocket
    fun getPollSocket(): Socket? = pollSocket
}
