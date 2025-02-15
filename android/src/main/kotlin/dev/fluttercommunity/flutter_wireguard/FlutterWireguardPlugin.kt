package dev.fluttercommunity.flutter_wireguard

import android.app.Activity
import android.content.Context
import android.content.Intent
import com.wireguard.android.backend.GoBackend
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val permissionRequestCode = 10014

class FlutterWireguardPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, ActivityAware, ActivityResultListener {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private lateinit var wireguard: Wireguard
    private var activity: Activity? = null
    private var permission: Boolean = false
    private var eventSink: EventChannel.EventSink? = null
    private val ioCoroutineScope = CoroutineScope(Dispatchers.IO)

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(flutterPluginBinding.binaryMessenger, "dev.fluttercommunity.flutter_wireguard/methodChannel")
        methodChannel.setMethodCallHandler(this)
        eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "dev.fluttercommunity.flutter_wireguard/eventChannel")
        wireguard = Wireguard.getInstance(flutterPluginBinding.applicationContext)
        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
                ioCoroutineScope.launch {
                    wireguard.tunnelStatusFlow.collect { tunnelStatuses ->
                        tunnelStatuses.forEach { (name, status) ->
                            withContext(Dispatchers.Main) {
                                eventSink?.success(mapOf(
                                    "name" to name,
                                    "state" to status.state.toString(),
                                    "rx" to status.rx,
                                    "tx" to status.tx
                                ))
                            }
                        }
                    }
                }
            }

            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })
    }

    override fun onDetachedFromEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        eventSink = null
        ioCoroutineScope.cancel()
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "start" -> {
                if (!permission) {
                    result.error("Failed to start tunnel", "User denied permission", null)
                    return
                }
                try {
                    wireguard.start(call.argument("name")!!, call.argument("config")!!)
                    result.success(null)
                } catch (e: Exception) {
                    wireguard.stop(call.argument("name")!!)
                    result.error("Failed to start tunnel", e.message, null)
                }
            }

            "stop" -> {
                if (!permission) {
                    result.error("Failed to stop tunnel", "User denied permission", null)
                    return
                }
                try {
                    wireguard.stop(call.argument("name")!!)
                    result.success(null)
                } catch (e: Exception) {
                    result.error("Failed to stop tunnel", e.message, null)
                }
            }

            "status" -> {
                if (!permission) {
                    result.error("Failed to stop tunnel", "User denied permission", null)
                    return
                }
                try {
                    val status = wireguard.status(call.argument("name")!!)
                    result.success(mapOf(
                        "name" to status.name,
                        "state" to status.state.toString(),
                        "rx" to status.rx,
                        "tx" to status.tx
                    ))
                } catch (e: Exception) {
                    result.error("Failed to stop tunnel", e.message, null)
                }
            }
            
            else -> result.notImplemented()
        }
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        activity = activityPluginBinding.activity
        getPermission()
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        activity = activityPluginBinding.activity
        getPermission()
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        permission = (requestCode == permissionRequestCode) && (resultCode == Activity.RESULT_OK)
        return permission
    }

    private fun getPermission() {
        if (permission) {
            return
        }

        val intent = if (wireguard.wgQuickBackend()) {
            GoBackend.VpnService.prepare(activity)
        } else if (wireguard.goBackend()) {
            GoBackend.VpnService.prepare(activity)
        } else {
            throw Exception("No backend available")
        }

        activity?.startActivityForResult(intent, permissionRequestCode)
    }
}
