package dev.fluttercommunity.flutter_wireguard

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.ByteArrayInputStream
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.util.RootShell
import com.wireguard.android.util.ToolsInstaller

class Wireguard private constructor(context: Context) {
    companion object {
        @Volatile
        private var instance: Wireguard? = null

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: Wireguard(context).also { instance = it }
            }
    }

    private var backend: Backend? = null
    private var rootShell: RootShell = RootShell(context)
    private var toolsInstaller: ToolsInstaller = ToolsInstaller(context, rootShell)
    private var tunnels: HashMap<String, Tunnel> = HashMap()
	data class Status(val name: String, val state: Tunnel.State,val rx: Long,val tx: Long,val handshake: Long)
    private val _tunnelStatusFlow = MutableStateFlow<Map<String, Status>>(emptyMap())
    val tunnelStatusFlow = _tunnelStatusFlow.asStateFlow()

    init {
        try {
            if (WgQuickBackend.hasKernelSupport()) {
                try {
                    rootShell.start()
                    val wgQuickBackend = WgQuickBackend(context, rootShell, toolsInstaller)
                    wgQuickBackend.setMultipleTunnels(true)
                    backend = wgQuickBackend
                    Log.i("WireGuard", "Using WgQuickBackend (kernel module)")
                } catch (ignored: Exception) {
                    Log.w("WireGuard", "WgQuickBackend initialization failed", ignored)
                }
            }
            if (backend == null) {
                backend = GoBackend(context)
                Log.i("WireGuard", "Using GoBackend (userspace)")
                // GoBackend logs automatically to logcat with tag "WireGuard/GoBackend"
                // To see wireguard-go logs, use: adb logcat -s "WireGuard/GoBackend"
            }
        } catch (e: Throwable) {
            throw Exception("Failed to initialize WireGuard backend", e)
        }
    }

    fun goBackend() : Boolean = backend is GoBackend
    fun wgQuickBackend() : Boolean = backend is WgQuickBackend

    fun start(name: String, config:String) {
        Log.i("WireGuard", "Starting tunnel: $name")
        backend!!.setState(tunnel(name), Tunnel.State.UP, com.wireguard.config.Config.parse(ByteArrayInputStream(config.toByteArray())))
        Log.i("WireGuard", "Tunnel started: $name")
    }

    fun stop(name: String) {
        Log.i("WireGuard", "Stopping tunnel: $name")
        backend!!.setState(tunnel(name), Tunnel.State.DOWN, null)
        Log.i("WireGuard", "Tunnel stopped: $name")
    }

    fun status(name: String):Status {
        val tun = tunnel(name)
        val stats  = backend!!.getStatistics(tun)
        val rx = stats.totalRx()
        val tx = stats.totalTx()
		var latestHandshake = 0L
		for (peerKey in stats.peers()) {
			val peerStats = stats.peer(peerKey)
			if (peerStats != null) {
				val hs = peerStats.latestHandshakeEpochMillis
				if (hs > latestHandshake) latestHandshake = hs
			}
		}
		return Status(name,backend!!.getState(tunnel(name)),rx,tx,latestHandshake)
    }

	fun handshake(name: String): Long {
		val stats = backend!!.getStatistics(tunnel(name))
		var latestHandshake = 0L
		for (peerKey in stats.peers()) {
			val peerStats = stats.peer(peerKey)
			if (peerStats != null) {
				val hs = peerStats.latestHandshakeEpochMillis
				if (hs > latestHandshake) latestHandshake = hs
			}
		}
		return latestHandshake
	}

    private fun tunnel(name: String): Tunnel =
        tunnels.getOrPut(name) {
            object : Tunnel {
                override fun getName():String = name
                override fun onStateChange(state: Tunnel.State) {
                    Log.i("WireGuard", "Tunnel $name state changed to: $state")
                    val stats  = backend!!.getStatistics(this)
                    val rx = stats.totalRx()
                    val tx = stats.totalTx()
					var latestHandshake = 0L
					for (peerKey in stats.peers()) {
						val peerStats = stats.peer(peerKey)
						if (peerStats != null) {
							val hs = peerStats.latestHandshakeEpochMillis
							if (hs > latestHandshake) latestHandshake = hs
						}
					}
                    Log.d("WireGuard", "Stats - rx: $rx, tx: $tx, handshake: $latestHandshake")
                    _tunnelStatusFlow.value = _tunnelStatusFlow.value.toMutableMap().apply {
						put(name, Status(name,state,rx,tx,latestHandshake))
                    }
                }
            }
        }
}

