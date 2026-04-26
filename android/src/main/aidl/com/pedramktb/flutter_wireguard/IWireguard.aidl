package com.pedramktb.flutter_wireguard;

import com.pedramktb.flutter_wireguard.IWireguardCallback;

// Binder interface exposed by WireguardService running in the :wireguard process.
// All blocking calls — invoke from a background thread.
interface IWireguard {
    // Start/stop a named tunnel. Blocking until the backend state change completes.
    void start(String name, String config);
    void stop(String name);

    // Returns current tunnel status as JSON: {name,state,rx,tx,handshake}.
    String statusJson(String name);

    // Names of every tunnel that has been touched in this process lifetime.
    String[] tunnelNames();

    // Returns backend info as JSON: {"kind":"kernel|userspace|unknown","detail":"..."}.
    String backendJson();

    // Register/unregister a callback for live status updates.
    // oneway = fire-and-forget; never blocks the calling thread (main thread safe).
    oneway void registerCallback(IWireguardCallback callback);
    oneway void unregisterCallback(IWireguardCallback callback);
}
