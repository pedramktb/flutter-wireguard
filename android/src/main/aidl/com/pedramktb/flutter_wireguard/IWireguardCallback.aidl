package com.pedramktb.flutter_wireguard;

// Callbacks delivered from the :wireguard process to the main process.
// oneway = non-blocking fire-and-forget (caller never waits for return).
oneway interface IWireguardCallback {
    void onTunnelStatus(String name, String state, long rx, long tx, long handshake);
}
