package dev.fluttercommunity.flutter_wireguard

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

private const val permissionRequestCode = 10014

/**
 * Runs in the MAIN process alongside Flutter
 *
 * It never imports GoBackend and never calls System.loadLibrary("wg-go"), so
 * the wireguard-go runtime stays isolated in the ':wireguard' process where
 * WireguardService lives.
 *
 * VPN permission is requested here because it needs a foreground Activity.
 * android.net.VpnService.prepare() (the base class) is used — it does not load
 * any WireGuard native library.
 */
class FlutterWireguardPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, ActivityResultListener {

    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel

    private var appContext: Context? = null
    private var activity: Activity? = null
    private var eventSink: EventChannel.EventSink? = null

    // Background scope for blocking cross-process AIDL calls.
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    // EventSink must be touched on the main thread.
    private val mainHandler = Handler(Looper.getMainLooper())

    // Binder proxy to WireguardService running in ':wireguard' process.
    @Volatile private var wireguardService: IWireguard? = null

    // Guard against rebinding during teardown (onDetachedFromEngine).
    @Volatile private var isEngineAttached = false

    // Stored binding reference for removing the ActivityResultListener on detach.
    private var activityBinding: ActivityPluginBinding? = null

    // ------------------------------------------------------------------
    // Service connection
    // ------------------------------------------------------------------

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val svc = IWireguard.Stub.asInterface(binder)
            try {
                svc.registerCallback(wireguardCallback)
                wireguardService = svc
            } catch (_: Exception) {
                // Binder failure during registration; clear and retry.
                wireguardService = null
                appContext?.let { bindWireguardService(it) }
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            // Remote ':wireguard' process was killed; attempt to rebind only if still attached.
            wireguardService = null
            if (isEngineAttached) {
                appContext?.let { bindWireguardService(it) }
            }
        }
    }

    // Receives live status events from WireguardService (called on a Binder thread).
    private val wireguardCallback = object : IWireguardCallback.Stub() {
        override fun onTunnelStatus(
            name: String, state: String, rx: Long, tx: Long, handshake: Long
        ) {
            mainHandler.post {
                eventSink?.success(
                    mapOf(
                        "name" to name,
                        "state" to state,
                        "rx" to rx,
                        "tx" to tx,
                        "handshake" to handshake
                    )
                )
            }
        }
    }

    private fun bindWireguardService(ctx: Context) {
        val intent = Intent(ctx, WireguardService::class.java)
        ctx.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    // ------------------------------------------------------------------
    // FlutterPlugin
    // ------------------------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        isEngineAttached = true
        appContext = binding.applicationContext

        methodChannel = MethodChannel(
            binding.binaryMessenger,
            "dev.fluttercommunity.flutter_wireguard/methodChannel"
        )
        methodChannel.setMethodCallHandler(this)

        eventChannel = EventChannel(
            binding.binaryMessenger,
            "dev.fluttercommunity.flutter_wireguard/eventChannel"
        )
        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
            }
            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })

        bindWireguardService(binding.applicationContext)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // Mark as detached before unbind to prevent onServiceDisconnected from rebinding.
        isEngineAttached = false
        eventSink = null
        try { wireguardService?.unregisterCallback(wireguardCallback) } catch (_: Exception) {}
        try { appContext?.unbindService(serviceConnection) } catch (_: Exception) {}

        wireguardService = null
        appContext = null

        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        scope.cancel(CancellationException("Plugin detached"))
    }

    // ------------------------------------------------------------------
    // MethodCallHandler
    // ------------------------------------------------------------------

    override fun onMethodCall(call: MethodCall, result: Result) {
        val svc = wireguardService
        if (svc == null) {
            result.error("NOT_CONNECTED", "WireguardService not yet bound", null)
            return
        }

        when (call.method) {
            "start" -> {
                val name: String = call.argument("name")!!
                val config: String = call.argument("config")!!
                // AIDL start() blocks until GoBackend state change completes — run on IO.
                scope.launch {
                    try {
                        svc.start(name, config)
                        mainHandler.post { result.success(null) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("START_FAILED", e.message, null) }
                    }
                }
            }

            "stop" -> {
                val name: String = call.argument("name")!!
                scope.launch {
                    try {
                        svc.stop(name)
                        mainHandler.post { result.success(null) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("STOP_FAILED", e.message, null) }
                    }
                }
            }

            "status" -> {
                val name: String = call.argument("name")!!
                scope.launch {
                    try {
                        val obj = JSONObject(svc.statusJson(name))
                        val map = mapOf(
                            "name" to obj.getString("name"),
                            "state" to obj.getString("state"),
                            "rx" to obj.getLong("rx"),
                            "tx" to obj.getLong("tx"),
                            "handshake" to obj.getLong("handshake")
                        )
                        mainHandler.post { result.success(map) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("STATUS_FAILED", e.message, null) }
                    }
                }
            }

            "backendType" -> {
                scope.launch {
                    try {
                        val type = svc.backendType()
                        mainHandler.post { result.success(type) }
                    } catch (e: Exception) {
                        mainHandler.post { result.error("BACKEND_TYPE_FAILED", e.message, null) }
                    }
                }
            }

            else -> result.notImplemented()
        }
    }

    // ------------------------------------------------------------------
    // ActivityAware — VPN permission (no GoBackend involved)
    // ------------------------------------------------------------------

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        binding.addActivityResultListener(this)
        requestVpnPermission()
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        binding.addActivityResultListener(this)
        requestVpnPermission()
    }

    override fun onDetachedFromActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding = null
        activity = null
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding = null
        activity = null
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != permissionRequestCode) return false
        // Always consume the VPN permission result (granted or denied).
        return true
    }

    /**
     * Request VPN permission using the base android.net.VpnService — not GoBackend.VpnService.
     * This does NOT import or instantiate GoBackend so libwg-go.so is never mapped in the
     * main process.
     */
    private fun requestVpnPermission() {
        val act = activity ?: return
        val intent = VpnService.prepare(act)
        if (intent != null) {
            act.startActivityForResult(intent, permissionRequestCode)
        }
    }
}
