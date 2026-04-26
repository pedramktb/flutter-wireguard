package com.pedramktb.flutter_wireguard

import android.content.Context
import android.util.Log
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.util.RootShell
import com.wireguard.android.util.ToolsInstaller
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.io.ByteArrayInputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-wide WireGuard manager. Lives in the :wireguard process; never
 * loaded in the main Flutter process.
 *
 * Thread-safe: all public methods may be called from any thread, but the
 * underlying backend serializes its own state changes.
 */
class Wireguard private constructor(context: Context) {

    companion object {
        private const val TAG = "WireGuard"

        @Volatile private var instance: Wireguard? = null
        fun getInstance(context: Context): Wireguard =
            instance ?: synchronized(this) {
                instance ?: Wireguard(context.applicationContext).also { instance = it }
            }
    }

    enum class Kind { KERNEL, USERSPACE, UNKNOWN }
    data class Status(
        val name: String,
        val state: Tunnel.State,
        val rx: Long,
        val tx: Long,
        val handshake: Long,
    )
    data class BackendInfo(val kind: Kind, val detail: String)

    private val backend: Backend
    val backendInfo: BackendInfo

    private val tunnels = ConcurrentHashMap<String, Tunnel>()

    // replay=0 — late subscribers only see new events (status() is the snapshot API).
    private val _events = MutableSharedFlow<Status>(extraBufferCapacity = 32)
    val events = _events.asSharedFlow()

    init {
        var b: Backend? = null
        var info: BackendInfo? = null
        try {
            if (WgQuickBackend.hasKernelSupport()) {
                try {
                    val rootShell = RootShell(context)
                    rootShell.start()
                    val toolsInstaller = ToolsInstaller(context, rootShell)
                    b = WgQuickBackend(context, rootShell, toolsInstaller).apply {
                        setMultipleTunnels(true)
                    }
                    info = BackendInfo(Kind.KERNEL, "WgQuickBackend (kernel)")
                    Log.i(TAG, info.detail)
                } catch (e: Exception) {
                    Log.w(TAG, "WgQuickBackend init failed; falling back to GoBackend", e)
                }
            }
            if (b == null) {
                b = GoBackend(context)
                info = BackendInfo(Kind.USERSPACE, "GoBackend")
                Log.i(TAG, info.detail)
            }
        } catch (e: Throwable) {
            throw IllegalStateException("Failed to initialise WireGuard backend", e)
        }
        backend = b!!
        backendInfo = info!!
    }

    fun start(name: String, config: String) {
        Log.i(TAG, "Starting tunnel: $name")
        val parsed = com.wireguard.config.Config.parse(ByteArrayInputStream(config.toByteArray()))
        backend.setState(getOrCreateTunnel(name), Tunnel.State.UP, parsed)
        Log.i(TAG, "Tunnel started: $name")
    }

    fun stop(name: String) {
        val t = tunnels[name] ?: return
        Log.i(TAG, "Stopping tunnel: $name")
        backend.setState(t, Tunnel.State.DOWN, null)
        Log.i(TAG, "Tunnel stopped: $name")
    }

    fun status(name: String): Status {
        val t = tunnels[name]
            ?: throw NoSuchElementException("Tunnel '$name' is unknown")
        val state = backend.getState(t)
        return collectStatus(name, t, state)
    }

    fun tunnelNames(): List<String> = tunnels.keys.toList()

    private fun getOrCreateTunnel(name: String): Tunnel = tunnels.getOrPut(name) {
        object : Tunnel {
            override fun getName(): String = name
            override fun onStateChange(newState: Tunnel.State) {
                Log.i(TAG, "Tunnel $name -> $newState")
                val s = collectStatus(name, this, newState)
                _events.tryEmit(s)
            }
        }
    }

    private fun collectStatus(name: String, t: Tunnel, state: Tunnel.State): Status {
        // getStatistics may throw on a DOWN tunnel — guard it.
        val (rx, tx, hs) = if (state == Tunnel.State.UP) {
            try {
                val stats = backend.getStatistics(t)
                var latest = 0L
                for (key in stats.peers()) {
                    val ps = stats.peer(key) ?: continue
                    if (ps.latestHandshakeEpochMillis > latest) latest = ps.latestHandshakeEpochMillis
                }
                Triple(stats.totalRx(), stats.totalTx(), latest)
            } catch (e: Exception) {
                Log.w(TAG, "getStatistics failed for $name", e)
                Triple(0L, 0L, 0L)
            }
        } else Triple(0L, 0L, 0L)
        return Status(name, state, rx, tx, hs)
    }
}
