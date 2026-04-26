package com.pedramktb.flutter_wireguard

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.wireguard.android.backend.Tunnel
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

private const val PERMISSION_REQUEST_CODE = 10014

/**
 * Lives in the MAIN process. Implements the Pigeon-generated [WireguardHostApi]
 * by delegating to the [IWireguard] AIDL binder exported by [WireguardService]
 * (which lives in the :wireguard process and owns libwg-go.so).
 *
 * Status events are forwarded to Dart via [WireguardFlutterApi].
 */
class FlutterWireguardPlugin :
    FlutterPlugin,
    ActivityAware,
    ActivityResultListener,
    WireguardHostApi {

    private var appContext: Context? = null
    private var activity: Activity? = null
    private var activityBinding: ActivityPluginBinding? = null
    private var flutterApi: WireguardFlutterApi? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile private var wireguardService: IWireguard? = null
    @Volatile private var isEngineAttached = false

    private val callback = object : IWireguardCallback.Stub() {
        override fun onTunnelStatus(
            name: String, state: String, rx: Long, tx: Long, handshake: Long
        ) {
            mainHandler.post {
                flutterApi?.onTunnelStatus(
                    TunnelStatus(
                        name = name,
                        state = state.toPigeonState(),
                        rx = rx,
                        tx = tx,
                        handshake = handshake,
                    )
                ) { /* ignore reply */ }
            }
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val svc = IWireguard.Stub.asInterface(binder)
            try {
                svc.registerCallback(callback)
                wireguardService = svc
            } catch (_: Exception) {
                wireguardService = null
                appContext?.let { rebind(it) }
            }
        }
        override fun onServiceDisconnected(name: ComponentName) {
            wireguardService = null
            if (isEngineAttached) appContext?.let { rebind(it) }
        }
    }

    private fun rebind(ctx: Context) {
        ctx.bindService(Intent(ctx, WireguardService::class.java), serviceConnection, Context.BIND_AUTO_CREATE)
    }

    // ---- FlutterPlugin -------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        isEngineAttached = true
        appContext = binding.applicationContext
        WireguardHostApi.setUp(binding.binaryMessenger, this)
        flutterApi = WireguardFlutterApi(binding.binaryMessenger)
        rebind(binding.applicationContext)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        isEngineAttached = false
        try { wireguardService?.unregisterCallback(callback) } catch (_: Exception) {}
        try { appContext?.unbindService(serviceConnection) } catch (_: Exception) {}
        wireguardService = null
        WireguardHostApi.setUp(binding.binaryMessenger, null)
        flutterApi = null
        appContext = null
        scope.cancel(CancellationException("Plugin detached"))
    }

    // ---- ActivityAware (VPN permission) -------------------------------

    override fun onAttachedToActivity(binding: ActivityPluginBinding) = bindActivity(binding)
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = bindActivity(binding)
    override fun onDetachedFromActivity() = unbindActivity()
    override fun onDetachedFromActivityForConfigChanges() = unbindActivity()

    private fun bindActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        binding.addActivityResultListener(this)
        requestVpnPermission()
    }

    private fun unbindActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding = null
        activity = null
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean =
        requestCode == PERMISSION_REQUEST_CODE

    private fun requestVpnPermission() {
        val act = activity ?: return
        val intent = VpnService.prepare(act)
        if (intent != null) act.startActivityForResult(intent, PERMISSION_REQUEST_CODE)
    }

    // ---- WireguardHostApi (Pigeon) ------------------------------------

    private inline fun <T> withService(
        errorCode: String,
        crossinline callback: (Result<T>) -> Unit,
        crossinline block: (IWireguard) -> T,
    ) {
        val svc = wireguardService
        if (svc == null) {
            callback(Result.failure(FlutterError("NOT_CONNECTED", "WireguardService not yet bound")))
            return
        }
        scope.launch {
            try {
                val r = block(svc)
                mainHandler.post { callback(Result.success(r)) }
            } catch (e: Exception) {
                mainHandler.post { callback(Result.failure(FlutterError(errorCode, e.message ?: e.javaClass.simpleName))) }
            }
        }
    }

    override fun start(name: String, config: String, callback: (Result<Unit>) -> Unit) =
        withService("START_FAILED", callback) { it.start(name, config) }

    override fun stop(name: String, callback: (Result<Unit>) -> Unit) =
        withService("STOP_FAILED", callback) { it.stop(name) }

    override fun status(name: String, callback: (Result<TunnelStatus>) -> Unit) =
        withService("STATUS_FAILED", callback) {
            val o = JSONObject(it.statusJson(name))
            TunnelStatus(
                name = o.getString("name"),
                state = o.getString("state").toPigeonState(),
                rx = o.getLong("rx"),
                tx = o.getLong("tx"),
                handshake = o.getLong("handshake"),
            )
        }

    override fun tunnelNames(callback: (Result<List<String>>) -> Unit) =
        withService("TUNNELS_FAILED", callback) { it.tunnelNames().toList() }

    override fun backend(callback: (Result<BackendInfo>) -> Unit) =
        withService("BACKEND_FAILED", callback) {
            val o = JSONObject(it.backendJson())
            BackendInfo(kind = o.getString("kind").toPigeonBackend(), detail = o.getString("detail"))
        }
}

internal fun String.toPigeonState(): TunnelState = when (Tunnel.State.valueOf(this)) {
    Tunnel.State.UP -> TunnelState.UP
    Tunnel.State.DOWN -> TunnelState.DOWN
    Tunnel.State.TOGGLE -> TunnelState.TOGGLE
}

internal fun String.toPigeonBackend(): BackendKind = when (this) {
    "kernel" -> BackendKind.KERNEL
    "userspace" -> BackendKind.USERSPACE
    else -> BackendKind.UNKNOWN
}
