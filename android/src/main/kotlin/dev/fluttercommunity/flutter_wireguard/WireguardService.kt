package dev.fluttercommunity.flutter_wireguard

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.RemoteCallbackList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Runs in the ':wireguard' process (declared in AndroidManifest.xml).
 *
 * This isolates libwg-go.so (wireguard-go, embedded inside com.wireguard.android:tunnel)
 * from libnetxlib.so in the main process.  Two Go runtimes built with different Go versions
 * cannot safely coexist in the same process address space, because each embeds its own
 * signal handlers, goroutine scheduler, and GC root tables.
 *
 * All WireGuard work (GoBackend, tunnels, VPN socket) stays in this process.
 * The main Flutter process communicates via the IWireguard AIDL binder and receives
 * live status updates through IWireguardCallback (oneway, non-blocking).
 */
class WireguardService : Service() {

    private lateinit var wireguard: Wireguard
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Thread-safe list of remotely registered callbacks (main-process binder proxies).
    private val callbacks = RemoteCallbackList<IWireguardCallback>()

    // ------------------------------------------------------------------
    // AIDL binder implementation
    // ------------------------------------------------------------------

    private val binder = object : IWireguard.Stub() {

        override fun start(name: String, config: String) {
            wireguard.start(name, config)
        }

        override fun stop(name: String) {
            wireguard.stop(name)
        }

        override fun statusJson(name: String): String? {
            return try {
                val s = wireguard.status(name)
                JSONObject().apply {
                    put("name", s.name)
                    put("state", s.state.toString())
                    put("rx", s.rx)
                    put("tx", s.tx)
                    put("handshake", s.handshake)
                }.toString()
            } catch (_: Exception) {
                null
            }
        }

        override fun backendType(): String = wireguard.backendType()

        override fun registerCallback(callback: IWireguardCallback) {
            callbacks.register(callback)
        }

        override fun unregisterCallback(callback: IWireguardCallback) {
            callbacks.unregister(callback)
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        wireguard = Wireguard.getInstance(applicationContext)

        // Forward tunnel status changes to all registered remote callbacks.
        scope.launch {
            wireguard.tunnelStatusFlow.collect { statuses ->
                statuses.forEach { (name, status) ->
                    val count = callbacks.beginBroadcast()
                    for (i in 0 until count) {
                        try {
                            callbacks.getBroadcastItem(i).onTunnelStatus(
                                name,
                                status.state.toString(),
                                status.rx,
                                status.tx,
                                status.handshake
                            )
                        } catch (_: Exception) {
                            // Dead callback; RemoteCallbackList removes it automatically.
                        }
                    }
                    callbacks.finishBroadcast()
                }
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
