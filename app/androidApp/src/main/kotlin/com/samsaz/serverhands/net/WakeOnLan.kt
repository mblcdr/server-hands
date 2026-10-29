package com.samsaz.serverhands.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** Builds and broadcasts Wake-on-LAN magic packets. */
object WakeOnLan {
    private const val PORT = 9

    /** Normalises "aa:bb:cc:dd:ee:ff", "AA-BB-..." or "aabbccddeeff" to lower-case colon form; null when it is not a MAC. */
    fun normalize(text: String): String? {
        val hex = text.trim().replace(Regex("[:\\-.]"), "").lowercase()
        if (!Regex("[0-9a-f]{12}").matches(hex)) return null
        return hex.chunked(2).joinToString(":")
    }

    /** 6 x 0xFF followed by the MAC 16 times. [mac] must come from [normalize]. */
    fun magicPacket(mac: String): ByteArray {
        val bytes = mac.split(":").map { it.toInt(16).toByte() }.toByteArray()
        return ByteArray(6) { 0xFF.toByte() } + ByteArray(16 * 6) { bytes[it % 6] }
    }

    /** Blocking; call off the main thread. */
    fun send(mac: String) {
        val data = magicPacket(mac)
        DatagramSocket().use { s ->
            s.broadcast = true
            s.send(DatagramPacket(data, data.size, InetAddress.getByName("255.255.255.255"), PORT))
        }
    }
}
