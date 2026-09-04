package com.bourass.fastdns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Android VPN Service implementing a system-wide FastDNS tunnel.
 *
 * Architecture:
 *   All phone traffic → tun0 → FastDnsEngine → DNS-over-TCP → Inwi Resolver → FastDNS Server
 *
 * This replaces FaizVPN's TcpInjectorVpnService + libhev-socks5-tunnel
 * with a direct IP-packet-level tunnel approach.
 */
class FastDnsVpnService : VpnService() {

    companion object {
        private const val TAG = "FastDnsVpnService"
        private const val CHANNEL_ID = "fastdns_vpn"
        private const val NOTIFICATION_ID = 1
        const val ACTION_CONNECT = "com.bourass.fastdns.CONNECT"
        const val ACTION_DISCONNECT = "com.bourass.fastdns.DISCONNECT"

        @Volatile
        var instance: FastDnsVpnService? = null
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var engine: FastDnsEngine? = null
    private var tunReadThread: Thread? = null
    @Volatile
    private var running = false

    // Status callback for UI
    var statusCallback: ((String) -> Unit)? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopTunnel()
        instance = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                // Start or reconnect
                startTunnel()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked")
        stopTunnel()
        stopSelf()
    }

    private fun startTunnel() {
        if (running) return
        running = true

        // Start foreground notification
        startForeground(NOTIFICATION_ID, buildNotification("Connecting..."))

        Thread(Runnable {
            try {
                performTunnelSetup()
            } catch (e: Exception) {
                Log.e(TAG, "Tunnel setup failed", e)
                updateNotification("Error: ${e.message}")
                stopTunnel()
            }
        }, "FastDNS-Setup").start()
    }

    private fun performTunnelSetup() {
        // 1. Create FastDNS engine
        val eng = FastDnsEngine()
        engine = eng

        eng.onStatusChange = { status ->
            Log.i(TAG, "Status: $status")
            updateNotification(status)
            statusCallback?.invoke(status)
        }

        eng.onError = { error ->
            Log.e(TAG, "Engine error: $error")
            updateNotification("Error: $error")
            statusCallback?.invoke("Error: $error")
        }

        // 2. Connect the FastDNS engine (TCP to resolver)
        eng.connect()

        // Wait for connection
        var waitCount = 0
        while (!eng.isConnected.get() && waitCount < 100 && running) {
            Thread.sleep(100)
            waitCount++
        }

        if (!eng.isConnected.get()) {
            Log.e(TAG, "Engine did not connect in time")
            return
        }

        // 3. Protect the engine's sockets from being routed through VPN
        eng.getDataSocket()?.let { protect(it) }
        eng.getPollSocket()?.let { protect(it) }

        // 4. Create the TUN interface
        val assignedIp = eng.assignedIp.ifEmpty { "10.8.0.2" }
        val builder = Builder()
            .setSession("Bourass FastDNS")
            .addAddress(assignedIp, 24)
            .addRoute("0.0.0.0", 0) // Route all IPv4 traffic
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .setMtu(1400)
            .setBlocking(true)

        // Exclude our own app from the VPN to prevent infinite loops
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude own package: ${e.message}")
        }

        vpnInterface = builder.establish()

        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN interface")
            updateNotification("Error: Failed to create VPN")
            return
        }

        Log.i(TAG, "VPN interface established (tun0)")
        updateNotification("Connected ✓ ($assignedIp)")
        statusCallback?.invoke("Connected ✓ IP: $assignedIp")

        // 5. Set up downlink: engine delivers packets → write to tun
        val tunFd = vpnInterface!!.fileDescriptor
        val tunOutput = FileOutputStream(tunFd)

        eng.onDownlinkPacket = { packet ->
            try {
                if (packet.size >= 20) { // Minimum IPv4 header
                    synchronized(tunOutput) {
                        tunOutput.write(packet)
                        tunOutput.flush()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error writing to tun: ${e.message}")
            }
        }

        // 6. Start reading from tun (uplink)
        tunReadThread = Thread(Runnable {
            val buffer = ByteBuffer.allocate(1500)
            val tunInput = FileInputStream(tunFd)

            while (running) {
                try {
                    buffer.clear()
                    val length = tunInput.read(buffer.array())
                    if (length > 0) {
                        val packet = buffer.array().copyOfRange(0, length)
                        eng.sendUplink(packet)
                    }
                } catch (e: Exception) {
                    if (running) {
                        Log.e(TAG, "Error reading from tun: ${e.message}")
                        Thread.sleep(100)
                    }
                }
            }
        }, "FastDNS-TunRead")
        tunReadThread?.start()

        // 7. Start speed monitoring
        Thread(Runnable { speedMonitor() }, "FastDNS-Speed").start()
    }

    private fun speedMonitor() {
        var lastSent = 0L
        var lastRecv = 0L

        while (running) {
            Thread.sleep(2000)
            val eng = engine ?: continue
            if (!eng.isConnected.get()) continue

            val sent = eng.bytesSent.get()
            val recv = eng.bytesReceived.get()
            val upSpeed = (sent - lastSent) / 2
            val downSpeed = (recv - lastRecv) / 2
            lastSent = sent
            lastRecv = recv

            val statusText = "↑ ${formatSpeed(upSpeed)} ↓ ${formatSpeed(downSpeed)}"
            updateNotification("Connected ✓ $statusText")
        }
    }

    private fun formatSpeed(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1_000_000 -> String.format("%.1f MB/s", bytesPerSec / 1_000_000.0)
            bytesPerSec >= 1_000 -> String.format("%.0f KB/s", bytesPerSec / 1_000.0)
            else -> "$bytesPerSec B/s"
        }
    }

    fun stopTunnel() {
        running = false

        engine?.disconnect()
        engine = null

        tunReadThread?.interrupt()
        tunReadThread = null

        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        stopForeground(true)
        statusCallback?.invoke("Disconnected")
    }

    // ---- Notification Helpers ----

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "FastDNS VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows FastDNS tunnel status"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = PendingIntent.getService(
            this, 1,
            Intent(this, FastDnsVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Bourass FastDNS")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_delete, "Disconnect", disconnectIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTIFICATION_ID, buildNotification(status))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification: ${e.message}")
        }
    }
}
