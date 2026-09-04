package com.bourass.fastdns

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private val VPN_REQUEST_CODE = 0x0F
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var tvStatus: TextView
    private lateinit var tvServer: TextView
    private lateinit var tvSpeed: TextView
    private lateinit var btnConnect: Button
    private lateinit var btnDisconnect: Button

    private var isConnected = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        tvServer = findViewById(R.id.tvServer)
        tvSpeed = findViewById(R.id.tvSpeed)
        btnConnect = findViewById(R.id.btnConnect)
        btnDisconnect = findViewById(R.id.btnDisconnect)

        tvServer.text = "DNS Server: 105.73.34.105:53\nZone: dns3.marocdns.uk"

        btnConnect.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST_CODE)
            } else {
                startVpn()
            }
        }

        btnDisconnect.setOnClickListener {
            stopVpn()
        }

        // Bind to service status updates
        updateUiState()
    }

    override fun onResume() {
        super.onResume()
        FastDnsVpnService.instance?.statusCallback = { status ->
            handler.post {
                tvStatus.text = status
                updateUiState()
            }
        }
        // Start speed updater
        startSpeedUpdater()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        val vpnIntent = Intent(this, FastDnsVpnService::class.java)
        vpnIntent.action = FastDnsVpnService.ACTION_CONNECT
        startService(vpnIntent)
        isConnected = true
        tvStatus.text = "Connecting..."
        updateUiState()
    }

    private fun stopVpn() {
        val vpnIntent = Intent(this, FastDnsVpnService::class.java)
        vpnIntent.action = FastDnsVpnService.ACTION_DISCONNECT
        startService(vpnIntent)
        isConnected = false
        tvStatus.text = "Disconnected"
        tvSpeed.text = ""
        updateUiState()
    }

    private fun updateUiState() {
        val serviceRunning = FastDnsVpnService.instance?.let {
            it.statusCallback != null
        } ?: false

        btnConnect.isEnabled = !isConnected
        btnDisconnect.isEnabled = isConnected
    }

    private fun startSpeedUpdater() {
        handler.postDelayed(object : Runnable {
            override fun run() {
                val eng = FastDnsVpnService.instance
                if (eng != null) {
                    // Speed is shown via notification; also show here
                }
                if (!isDestroyed) {
                    handler.postDelayed(this, 2000)
                }
            }
        }, 2000)
    }
}
