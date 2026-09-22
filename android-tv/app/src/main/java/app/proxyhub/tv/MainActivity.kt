package app.proxyhub.tv

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.PorterDuff
import android.net.VpnService
import android.os.Bundle
import android.widget.ImageButton

class MainActivity : Activity() {
    private lateinit var power: ImageButton
    private val listener: (Boolean) -> Unit = { on ->
        if (!isFinishing) paint(on)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        power = findViewById(R.id.power)
        power.setOnClickListener { toggle() }
        power.requestFocus()
        paint(ProxyVpnService.isRunning)
    }

    override fun onResume() {
        super.onResume()
        ProxyVpnService.listener = listener
        paint(ProxyVpnService.isRunning)
        power.requestFocus()
    }

    override fun onPause() {
        if (ProxyVpnService.listener === listener) {
            ProxyVpnService.listener = null
        }
        super.onPause()
    }

    private fun toggle() {
        if (ProxyVpnService.isRunning) {
            stopService(Intent(this, ProxyVpnService::class.java))
            paint(false)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            start()
        }
    }

    @Deprecated("Activity Result API needs AndroidX; this dialog is the platform VPN consent.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            start()
        }
    }

    private fun start() {
        startService(Intent(this, ProxyVpnService::class.java))
        paint(true)
    }

    private fun paint(on: Boolean) {
        val color = if (on) Color.parseColor("#3DDC84") else Color.parseColor("#8B95A1")
        power.setColorFilter(color, PorterDuff.Mode.SRC_IN)
    }

    companion object {
        private const val REQUEST_VPN = 1
    }
}
