package dev.fluttercommunity.flutter_wireguard

import android.app.Activity
import android.content.Context
import android.content.Intent
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.BackendException
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
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val permissionRequestCode = 10014

class FlutterWireguardPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, ActivityResultListener {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private lateinit var wireguard: Wireguard
    private var activity: Activity? = null
    private var permission: Boolean = false
    private var eventSink: EventChannel.EventSink? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(flutterPluginBinding.binaryMessenger, "dev.fluttercommunity.flutter_wireguard/methodChannel")
        methodChannel.setMethodCallHandler(this)
        eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "dev.fluttercommunity.flutter_wireguard/eventChannel")
        wireguard = Wireguard.getInstance(flutterPluginBinding.applicationContext)
        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
                scope.launch {
                    wireguard.tunnelStatusFlow.collect { tunnelStatuses ->
                        tunnelStatuses.forEach { (name, status) ->
                            withContext(Dispatchers.Main) {
                                eventSink?.success(mapOf(
                                        "name" to name,
                                        "state" to status.state.toString(),
                                        "rx" to status.rx,
                                        "tx" to status.tx,
                                        "handshake" to status.handshake
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
        scope.cancel(CancellationException("Plugin detached"))
        eventSink = null
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "start" -> {
                scope.launch {
                    wireguard.start(call.argument("name")!!, call.argument("config")!!)
                    result.success(null)
                }
            }
            "stop" -> {

                scope.launch {
                    wireguard.stop(call.argument("name")!!)
                    result.success(null)

                }
            }
            "status" -> {
                scope.launch {
                    val status = wireguard.status(call.argument("name")!!)
                    result.success(mapOf(
                            "name" to status.name,
                            "state" to status.state.toString(),
                            "rx" to status.rx,
                            "tx" to status.tx,
                            "handshake" to status.handshake
                    ))
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
            null
        } else if (wireguard.goBackend()) {
            GoBackend.VpnService.prepare(activity)
        } else {
            throw Exception("No backend available")
        }

        if (intent != null) {
            activity?.startActivityForResult(intent, permissionRequestCode)
        } else {
            permission = true;
        }
    }
}
