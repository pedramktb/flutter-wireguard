package com.pedramktb.flutter_wireguard;

import com.pedramktb.flutter_wireguard.IWireguardCallback;

// Binder interface exposed by WireguardService running in the :wireguard process.
interface IWireguard {
    // Start/stop a named tunnel. Blocking until the backend state change completes.
    void start(String name, String config);
    void stop(String name);

    // Returns current tunnel status as a JSON string, or null if the tunnel does not exist.
    String statusJson(String name);

    // Returns the active backend: "GoBackend" or "WgQuickBackend (kernel)".
    String backendType();

    // Register/unregister a callback for live status updates.
    // oneway = fire-and-forget; never blocks the calling thread (main thread safe).
    oneway void registerCallback(IWireguardCallback callback);
    oneway void unregisterCallback(IWireguardCallback callback);
}
