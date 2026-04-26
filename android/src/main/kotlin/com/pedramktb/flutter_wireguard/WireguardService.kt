package com.pedramktb.flutter_wireguard

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.RemoteCallbackList
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Runs in the ':wireguard' process. Owns Wireguard (and therefore libwg-go.so),
 * isolating the wireguard-go runtime from the main Flutter process.
 *
 * The main process talks to this service over [IWireguard] and receives live
 * status updates over [IWireguardCallback].
 */
class WireguardService : Service() {

    private lateinit var wireguard: Wireguard
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val callbacks = RemoteCallbackList<IWireguardCallback>()

    // AIDL only propagates a fixed set of exceptions across processes.
    // Generic RuntimeException is NOT one of them — it would surface as
    // "Uncaught remote exception" and the client sees a successful return.
    // IllegalStateException IS in the auto-propagated list, so we wrap any
    // failure as one and let the message survive the binder boundary.
    private inline fun <T> rethrow(block: () -> T): T = try {
        block()
    } catch (e: IllegalStateException) {
        throw e
    } catch (e: IllegalArgumentException) {
        throw e
    } catch (e: SecurityException) {
        throw e
    } catch (e: Exception) {
        throw IllegalStateException("${e.javaClass.simpleName}: ${e.message ?: ""}", e)
    }

    private val binder = object : IWireguard.Stub() {
        override fun start(name: String, config: String) = rethrow { wireguard.start(name, config) }
        override fun stop(name: String) = rethrow { wireguard.stop(name) }
        override fun statusJson(name: String): String = rethrow { wireguard.status(name).toJson() }
        override fun tunnelNames(): Array<String> = rethrow { wireguard.tunnelNames().toTypedArray() }
        override fun backendJson(): String = rethrow {
            JSONObject().apply {
                put("kind", wireguard.backendInfo.kind.name.lowercase())
                put("detail", wireguard.backendInfo.detail)
            }.toString()
        }
        override fun registerCallback(cb: IWireguardCallback) { callbacks.register(cb) }
        override fun unregisterCallback(cb: IWireguardCallback) { callbacks.unregister(cb) }
    }

    override fun onCreate() {
        super.onCreate()
        wireguard = Wireguard.getInstance(applicationContext)

        scope.launch {
            wireguard.events.collect { s ->
                val n = callbacks.beginBroadcast()
                for (i in 0 until n) {
                    try {
                        callbacks.getBroadcastItem(i).onTunnelStatus(
                            s.name, s.state.name, s.rx, s.tx, s.handshake
                        )
                    } catch (_: Exception) { /* dead callback removed by RemoteCallbackList */ }
                }
                callbacks.finishBroadcast()
            }
        }
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onDestroy() {
        scope.cancel()
        callbacks.kill()
        super.onDestroy()
    }
}

private fun Wireguard.Status.toJson(): String = JSONObject().apply {
    put("name", name)
    put("state", state.name)
    put("rx", rx)
    put("tx", tx)
    put("handshake", handshake)
}.toString()

internal fun parseStatusJson(json: String): Wireguard.Status {
    val o = JSONObject(json)
    return Wireguard.Status(
        name = o.getString("name"),
        state = Tunnel.State.valueOf(o.getString("state")),
        rx = o.getLong("rx"),
        tx = o.getLong("tx"),
        handshake = o.getLong("handshake"),
    )
}
