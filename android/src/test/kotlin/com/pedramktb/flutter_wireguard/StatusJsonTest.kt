package com.pedramktb.flutter_wireguard

import com.wireguard.android.backend.Tunnel
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class StatusJsonTest {

    @Test
    fun roundTrip() {
        val s = Wireguard.Status(
            name = "wg0",
            state = Tunnel.State.UP,
            rx = 12345L,
            tx = 67890L,
            handshake = 1700000000000L,
        )
        // Use the same encoding as WireguardService, then parse back via the
        // helper exposed in the same file.
        val json = org.json.JSONObject().apply {
            put("name", s.name)
            put("state", s.state.name)
            put("rx", s.rx)
            put("tx", s.tx)
            put("handshake", s.handshake)
        }.toString()

        val parsed = parseStatusJson(json)
        assertEquals(s, parsed)
    }

    @Test
    fun stateMappingMirrorsPigeon() {
        // String -> Pigeon enum mapping used by FlutterWireguardPlugin.
        assertEquals(TunnelState.UP, "UP".toPigeonState())
        assertEquals(TunnelState.DOWN, "DOWN".toPigeonState())
        assertEquals(TunnelState.TOGGLE, "TOGGLE".toPigeonState())
    }

    @Test
    fun backendKindMappingMirrorsPigeon() {
        assertEquals(BackendKind.KERNEL, "kernel".toPigeonBackend())
        assertEquals(BackendKind.USERSPACE, "userspace".toPigeonBackend())
        assertEquals(BackendKind.UNKNOWN, "anything-else".toPigeonBackend())
    }
}
