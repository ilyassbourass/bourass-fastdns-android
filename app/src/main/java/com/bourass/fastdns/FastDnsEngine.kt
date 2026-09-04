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
    private var zone: String = FastDnsCrypto.DEFAULT_ZONE,
    private var subId: String = FastDnsCrypto.DEFAULT_SUB_ID,
    private var installId: String = FastDnsCrypto.deriveInstallId(FastDnsCrypto.DEFAULT_SUB_ID)
) {
    companion object {
        private const val TAG = "FastDnsEngine"
        val RESOLVER_TARGETS = listOf("37.221.198.37", "105.73.34.105", "105.73.34.106")
        private const val CHUNK_LIMIT = 81
    }

    // Dynamic Account Pool
    private val accountPool = java.util.concurrent.CopyOnWriteArrayList<String>(FastDnsCrypto.INITIAL_POOL)
    private var poolIndex = 0

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
    private val rotating = AtomicBoolean(false)

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

        // Start downlink poll loop, uplink worker, and background replenishment
        Thread(Runnable { pollLoop() }, "FastDNS-Poll").start()
        Thread(Runnable { uplinkLoop() }, "FastDNS-Uplink").start()
        startBackgroundReplenishment()
    }

    /**
     * Sends the 0-handshake-batch-zstd query across accounts in the pool.
     */
    private fun performHandshake(): Boolean {
        val cert = FastDnsCrypto.CERT_HEX
        val initialIdx = poolIndex

        for (attempt in 0 until accountPool.size) {
            val idx = (initialIdx + attempt) % accountPool.size
            val currentSub = accountPool[idx]
            val currentInst = FastDnsCrypto.deriveInstallId(currentSub)
            val currentSubKey = FastDnsCrypto.deriveSubKey(currentSub)
            val currentHsKey = FastDnsCrypto.deriveHandshakeKey(currentSubKey, currentInst)

            val qname = "0-handshake-batch-zstd.$currentSub.$currentInst.0.110.${cert.substring(0, 32)}.${cert.substring(32)}.$zone."
            Log.i(TAG, "Attempting handshake with subId=$currentSub, qname=$qname")

            for (target in RESOLVER_TARGETS) {
                try {
                    Log.i(TAG, "Attempting handshake with $target:$resolverPort")
                    val s = Socket()
                    s.tcpNoDelay = true
                    s.soTimeout = 6000
                    vpnService.protect(s)
                    s.connect(InetSocketAddress(target, resolverPort), 4000)

                    val out = BufferedOutputStream(s.getOutputStream(), 4096)
                    val inp = BufferedInputStream(s.getInputStream(), 65536)

                    val resp = sendDnsQuery(out, inp, qname)
                    try { s.close() } catch (_: Exception) {}

                    if (resp != null && resp.size > 29 && (resp[0].toInt() and 0xFF) == 0xF1) {
                        val nonce = resp.copyOfRange(1, 13)
                        val ciphertext = resp.copyOfRange(13, resp.size)
                        val plain = FastDnsCrypto.aesGcmDecrypt(currentHsKey, nonce, ciphertext)
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

                        subId = currentSub
                        installId = currentInst
                        subKey = currentSubKey
                        hsKey = currentHsKey
                        sessionKey = FastDnsCrypto.deriveSessionKey(subKey, installId, sessionHex)
                        poolIndex = (idx + 1) % accountPool.size

                        Log.i(TAG, "Session ready! subId=$subId, sid=$sessionHex, ip=$assignedIp, shortSess=$shortSess")
                        return true
                    } else {
                        Log.w(TAG, "Handshake resp invalid from $target for $currentSub: len=${resp?.size}")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Handshake attempt with $target ($currentSub) failed: ${e.message}")
                }
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
     * Synchronously sends one uplink IP packet with batch framing, Zstd compression,
     * and multi-chunk AES-GCM encryption matching the wire protocol.
     */
    private fun sendUplinkSync(data: ByteArray, out: OutputStream, inp: InputStream) {
        val sk = sessionKey ?: return
        val seq = uplinkSeq.getAndIncrement() and 0xFFFF

        // Batch framing: [length u16 BE] + [packet bytes]
        val batch = ByteArray(2 + data.size)
        batch[0] = (data.size shr 8).toByte()
        batch[1] = (data.size and 0xFF).toByte()
        System.arraycopy(data, 0, batch, 2, data.size)

        // Zstd compress
        val compressed = zstdCompress(batch)

        // Chunking across DNS limits
        val chunkLimit = CHUNK_LIMIT
        val totalChunks = (compressed.size + chunkLimit - 1) / chunkLimit

        for (chunkIdx in 0 until totalChunks) {
            val start = chunkIdx * chunkLimit
            val end = Math.min(start + chunkLimit, compressed.size)
            val chunkData = compressed.copyOfRange(start, end)

            // AES-GCM encrypt each chunk
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            val encrypted = FastDnsCrypto.aesGcmEncrypt(sk, iv, chunkData)

            // Wire frame: [seq u16 BE][chunkIdx u8][totalChunks u8][0xF1][iv (12)][ciphertext]
            val enc = byteArrayOf(0xF1.toByte()) + iv + encrypted
            val frame = byteArrayOf(
                (seq shr 8).toByte(),
                (seq and 0xFF).toByte(),
                chunkIdx.toByte(),
                totalChunks.toByte()
            ) + enc

            // Base32 encode
            val b32 = FastDnsCrypto.base32Encode(frame)
            val labels = b32.chunked(60)

            val qname = "0-${labels.joinToString(".")}.s$sessionHex.$zone."

            // Send query and read acknowledgment
            sendDnsQuery(out, inp, qname)
        }

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

                val pSeq = pollSeq.getAndIncrement() and 0xFFFF
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
        if (text == "ok") return
        if (text == "gone") {
            Log.w(TAG, "Downlink poll returned 'gone' — rotating account...")
            rotateAccountAndReconnect()
            return
        }

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

    /**
     * Performs a seamless account rotation when current session expires.
     */
    private fun rotateAccountAndReconnect() {
        if (!rotating.compareAndSet(false, true)) return
        Thread(Runnable {
            try {
                onStatusChange?.invoke("Rotating session...")
                Log.i(TAG, "Rotating to next account in pool...")
                val ok = performHandshake()
                if (ok) {
                    onStatusChange?.invoke("FastDNS Connected ✓ ($assignedIp)")
                    Log.i(TAG, "Account rotated successfully! sid=$sessionHex, ip=$assignedIp")
                } else {
                    Log.e(TAG, "Account rotation failed to handshake")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Account rotation error: ${e.message}", e)
            } finally {
                rotating.set(false)
            }
        }, "FastDNS-Rotate").start()
    }

    /**
     * Continuously replenishes the account pool with freshly provisioned accounts
     * every 10 minutes while tunnel is active.
     */
    private fun startBackgroundReplenishment() {
        Thread(Runnable {
            while (running.get()) {
                try {
                    Thread.sleep(10 * 60 * 1000) // 10 minutes
                    if (!isConnected.get() || !running.get()) continue

                    val randomBytes = ByteArray(8)
                    SecureRandom().nextBytes(randomBytes)
                    val newHwid = FastDnsCrypto.bytesToHex(randomBytes)

                    Log.i(TAG, "Provisioning fresh account $newHwid in background...")
                    val ok = FastDnsCrypto.provisionAccount(newHwid)
                    if (ok) {
                        accountPool.add(newHwid)
                        Log.i(TAG, "Background provisioned new account $newHwid! Pool size: ${accountPool.size}")
                    } else {
                        Log.w(TAG, "Background provisioning for $newHwid failed")
                    }
                } catch (_: InterruptedException) {
                    break
                } catch (e: Exception) {
                    Log.w(TAG, "Background replenishment notice: ${e.message}")
                }
            }
        }, "FastDNS-Replenish").start()
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


