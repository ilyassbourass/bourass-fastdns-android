package com.bourass.fastdns

import android.net.VpnService
import android.util.Log
import org.json.JSONObject
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * FastDNS Tunnel Engine matching FaizVPN wire protocol:
 *   - Verified handshake query fetching dynamic session ID and tunnel IP.
 *   - Session key derivation matching NativeKeys HMAC-SHA256 formula.
 *   - Zstandard (level 3) compression on uplink and decompression on downlink.
 *   - Dual dedicated TCP sockets (Uplink and Downlink Poll) with auto-reconnect.
 *   - Non-blocking packet queue bridging VpnService TUN interface to the network.
 */
class FastDnsEngine(
    private val vpnService: VpnService,
    private val resolverPort: Int = 53,
    private val zone: String = "dns3.marocdns.uk",
    private val subId: String = FastDnsCrypto.DEFAULT_SUB_ID,
    private val installId: String = FastDnsCrypto.DEFAULT_INSTALL_ID
) {
    companion object {
        private const val TAG = "FastDnsEngine"
        val RESOLVER_TARGETS = listOf("213.160.77.162", "105.73.34.106", "105.73.34.105")
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
    var assignedIp: String = "10.8.0.2"
        private set

    private var uplinkSeq = AtomicInteger((1..1000).random())
    private var pollSeq = AtomicInteger(0)

    // Uplink queue
    private val uplinkQueue = LinkedBlockingQueue<ByteArray>(300)

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
        uplinkQueue.clear()
        onStatusChange?.invoke("Disconnected")
    }

    private fun performConnect() {
        onStatusChange?.invoke("Deriving cryptographic keys...")

        subKey = FastDnsCrypto.deriveSubKey(subId)
        hsKey = FastDnsCrypto.deriveHandshakeKey(subKey, installId)

        // 1. Perform handshake with server to obtain real session and IP
        onStatusChange?.invoke("Connecting to FastDNS server...")
        val handshakeOk = performHandshake()
        if (!handshakeOk) {
            onError?.invoke("Handshake failed — no response from FastDNS servers")
            disconnect()
            return
        }

        isConnected.set(true)
        onStatusChange?.invoke("FastDNS Connected ✓ ($assignedIp)")
        Log.i(TAG, "FastDNS tunnel is ACTIVE with sid=$sessionHex, ip=$assignedIp")

        // 2. Start downlink poll loop and uplink worker
        Thread(Runnable { pollLoop() }, "FastDNS-Poll").start()
        Thread(Runnable { uplinkLoop() }, "FastDNS-Uplink").start()
    }

    /**
     * Sends the 0-handshake-batch-zstd query to discover session parameters.
     */
    private fun performHandshake(): Boolean {
        val cert = FastDnsCrypto.CERT_HEX
        val qname = "0-handshake-batch-zstd.$subId.$installId.0.110.${cert.substring(0, 32)}.${cert.substring(32)}.$zone."
        Log.i(TAG, "Handshake QNAME: $qname")

        for (target in RESOLVER_TARGETS) {
            try {
                Log.i(TAG, "Attempting handshake with $target:$resolverPort")
                val s = Socket()
                s.tcpNoDelay = true
                s.soTimeout = 8000
                vpnService.protect(s)
                s.connect(InetSocketAddress(target, resolverPort), 5000)

                val out = BufferedOutputStream(s.getOutputStream(), 4096)
                val inp = BufferedInputStream(s.getInputStream(), 65536)

                val resp = sendDnsQuery(out, inp, qname)
                try { s.close() } catch (_: Exception) {}

                if (resp != null && resp.size > 29 && (resp[0].toInt() and 0xFF) == 0xF1) {
                    val nonce = resp.copyOfRange(1, 13)
                    val ciphertext = resp.copyOfRange(13, resp.size)
                    val plain = FastDnsCrypto.aesGcmDecrypt(hsKey, nonce, ciphertext)
                    val jsonStr = String(plain, Charsets.UTF_8)
                    Log.i(TAG, "Handshake decrypted: $jsonStr")

                    val json = JSONObject(jsonStr)
                    sessionHex = json.getString("sid")
                    assignedIp = json.getString("ip")
                    shortSess = if (sessionHex.length >= 4) {
                        try {
                            Integer.parseInt(sessionHex.substring(0, 4), 16).toString()
                        } catch (_: Exception) {
                            "39928"
                        }
                    } else {
                        "39928"
                    }

                    sessionKey = FastDnsCrypto.deriveSessionKey(subKey, installId, sessionHex)
                    Log.i(TAG, "Session ready! sid=$sessionHex, ip=$assignedIp, shortSess=$shortSess")
                    return true
                } else {
                    Log.w(TAG, "Handshake resp invalid from $target: len=${resp?.size}")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Handshake attempt with $target failed: ${e.message}")
            }
        }
        return false
    }

    /**
     * Enqueue IP packet for uplink transmission.
     */
    fun sendUplink(data: ByteArray) {
        if (!isConnected.get() || sessionKey == null) return
        uplinkQueue.offer(data)
    }

    /**
     * Dedicated uplink worker thread.
     */
    private fun uplinkLoop() {
        Log.i(TAG, "Uplink worker started")
        var socket: Socket? = null
        var out: OutputStream? = null
        var inp: InputStream? = null
        var targetIdx = 0

        fun connectSocket(): Boolean {
            try { socket?.close() } catch (_: Exception) {}
            socket = null
            out = null
            inp = null

            for (i in RESOLVER_TARGETS.indices) {
                val idx = (targetIdx + i) % RESOLVER_TARGETS.size
                val target = RESOLVER_TARGETS[idx]
                try {
                    val s = Socket()
                    s.tcpNoDelay = true
                    s.soTimeout = 8000
                    vpnService.protect(s)
                    s.connect(InetSocketAddress(target, resolverPort), 5000)
                    socket = s
                    out = BufferedOutputStream(s.getOutputStream(), 16384)
                    inp = BufferedInputStream(s.getInputStream(), 4096)
                    targetIdx = idx
                    Log.i(TAG, "Uplink socket connected to $target:$resolverPort")
                    return true
                } catch (e: Exception) {
                    Log.w(TAG, "Uplink connect to $target failed: ${e.message}")
                }
            }
            return false
        }

        while (running.get() && isConnected.get()) {
            try {
                val packet = uplinkQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue

                if (socket == null || socket!!.isClosed || !socket!!.isConnected) {
                    if (!connectSocket()) {
                        Thread.sleep(500)
                        continue
                    }
                }

                sendUplinkSync(packet, out!!, inp!!)
            } catch (e: Exception) {
                if (running.get()) {
                    Log.w(TAG, "Uplink socket error: ${e.message} — reconnecting")
                    try { socket?.close() } catch (_: Exception) {}
                    socket = null
                    Thread.sleep(200)
                }
            }
        }

        try { socket?.close() } catch (_: Exception) {}
        Log.i(TAG, "Uplink worker stopped")
    }

    /**
     * Synchronously sends one uplink IP packet.
     */
    private fun sendUplinkSync(data: ByteArray, out: OutputStream, inp: InputStream) {
        val sk = sessionKey ?: return
        val seq = uplinkSeq.getAndIncrement()

        // Batch framing: [length u16 BE] + [packet bytes]
        val batch = ByteArray(2 + data.size)
        batch[0] = (data.size shr 8).toByte()
        batch[1] = (data.size and 0xFF).toByte()
        System.arraycopy(data, 0, batch, 2, data.size)

        // Zstd compress
        val compressed = zstdCompress(batch)

        // AES-GCM encrypt
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val encrypted = FastDnsCrypto.aesGcmEncrypt(sk, iv, compressed)

        // Wire frame: [seq u16 BE][0x00, 0x01][0xF1][iv (12)][ciphertext]
        val enc = byteArrayOf(0xF1.toByte()) + iv + encrypted
        val frame = byteArrayOf((seq shr 8).toByte(), (seq and 0xFF).toByte(), 0x00, 0x01) + enc

        // Base32 encode
        val b32 = FastDnsCrypto.base32Encode(frame)
        val firstLabel = "0-" + b32.take(61)
        val restLabels = if (b32.length > 61) b32.substring(61).chunked(63) else emptyList()
        val labels = listOf(firstLabel) + restLabels

        val qname = "${labels.joinToString(".")}.s$sessionHex.$zone."

        // Send query and read acknowledgment
        sendDnsQuery(out, inp, qname)
        bytesSent.addAndGet(data.size.toLong())
    }

    /**
     * Dedicated downlink poll loop thread.
     */
    private fun pollLoop() {
        Log.i(TAG, "Poll worker started for shortSess=$shortSess, ip=$assignedIp")
        var socket: Socket? = null
        var out: OutputStream? = null
        var inp: InputStream? = null
        var targetIdx = 0

        fun connectSocket(): Boolean {
            try { socket?.close() } catch (_: Exception) {}
            socket = null
            out = null
            inp = null

            for (i in RESOLVER_TARGETS.indices) {
                val idx = (targetIdx + i) % RESOLVER_TARGETS.size
                val target = RESOLVER_TARGETS[idx]
                try {
                    val s = Socket()
                    s.tcpNoDelay = true
                    s.soTimeout = 8000
                    vpnService.protect(s)
                    s.connect(InetSocketAddress(target, resolverPort), 5000)
                    socket = s
                    out = BufferedOutputStream(s.getOutputStream(), 16384)
                    inp = BufferedInputStream(s.getInputStream(), 32768)
                    targetIdx = idx
                    Log.i(TAG, "Poll socket connected to $target:$resolverPort")
                    return true
                } catch (e: Exception) {
                    Log.w(TAG, "Poll connect to $target failed: ${e.message}")
                }
            }
            return false
        }

        while (running.get() && isConnected.get()) {
            try {
                if (socket == null || socket!!.isClosed || !socket!!.isConnected) {
                    if (!connectSocket()) {
                        Thread.sleep(1000)
                        continue
                    }
                }

                val pSeq = pollSeq.getAndIncrement()
                val rand = (100000..999999).random()
                val qname = "0-poll.$shortSess.$pSeq.$rand.s$assignedIp.$zone."

                val resp = sendDnsQuery(out!!, inp!!, qname)
                if (resp != null && resp.isNotEmpty()) {
                    processDownlink(resp)
                }

                Thread.sleep(60)
            } catch (e: Exception) {
                if (running.get()) {
                    Log.w(TAG, "Poll notice: ${e.message} — reconnecting socket")
                    try { socket?.close() } catch (_: Exception) {}
                    socket = null
                    Thread.sleep(200)
                }
            }
        }

        try { socket?.close() } catch (_: Exception) {}
        Log.i(TAG, "Poll worker stopped")
    }

    /**
     * Decrypts and decompresses downlink response, passing IP packets to VpnService.
     */
    private fun processDownlink(data: ByteArray) {
        if (data.size <= 4) return
        val text = String(data, Charsets.UTF_8)
        if (text == "ok" || text == "gone") return

        val sk = sessionKey ?: return
        if (data.size > 29 && (data[0].toInt() and 0xFF) == 0xF1) {
            try {
                val nonce = data.copyOfRange(1, 13)
                val ciphertext = data.copyOfRange(13, data.size)
                val plain = FastDnsCrypto.aesGcmDecrypt(sk, nonce, ciphertext)

                // Decompress with Zstd
                val decompressed = zstdDecompress(plain)

                // Extract batched packets: [len u16 BE][packet]...
                var offset = 0
                while (offset + 2 <= decompressed.size) {
                    val pktLen = ((decompressed[offset].toInt() and 0xFF) shl 8) or
                            (decompressed[offset + 1].toInt() and 0xFF)
                    offset += 2
                    if (pktLen <= 0 || offset + pktLen > decompressed.size) {
                        if (offset == 2 && decompressed.size >= 20) {
                            bytesReceived.addAndGet(decompressed.size.toLong())
                            onDownlinkPacket?.invoke(decompressed)
                        }
                        break
                    }
                    val ipPacket = decompressed.copyOfRange(offset, offset + pktLen)
                    bytesReceived.addAndGet(ipPacket.size.toLong())
                    onDownlinkPacket?.invoke(ipPacket)
                    offset += pktLen
                }
            } catch (e: Exception) {
                Log.w(TAG, "Downlink decrypt/decompress error: ${e.message}")
            }
        }
    }

    // ---- Zstandard Helpers ----

    private fun zstdCompress(data: ByteArray): ByteArray {
        return com.github.luben.zstd.Zstd.compress(data, 3)
    }

    private fun zstdDecompress(data: ByteArray): ByteArray {
        val bais = ByteArrayInputStream(data)
        val zis = com.github.luben.zstd.ZstdInputStream(bais)
        val baos = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var n: Int
        while (zis.read(buf).also { n = it } > 0) {
            baos.write(buf, 0, n)
        }
        zis.close()
        return baos.toByteArray()
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

    private fun buildDnsPacket(txId: Int, qname: String): ByteArray {
        val buf = ByteArrayOutputStream()

        buf.write(byteArrayOf((txId shr 8).toByte(), (txId and 0xFF).toByte()))
        buf.write(byteArrayOf(0x01, 0x00)) // Flags: Standard query, RD=1
        buf.write(byteArrayOf(0x00, 0x01)) // QDCOUNT: 1
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

    fun getSocket(): Socket? = null
}


