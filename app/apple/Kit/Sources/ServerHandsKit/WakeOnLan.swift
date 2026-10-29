import Foundation

/// Builds and broadcasts Wake-on-LAN magic packets.
public enum WakeOnLan {
    static let port: UInt16 = 9

    /// Normalises "aa:bb:cc:dd:ee:ff", "AA-BB-..." or "aabbccddeeff" to lower-case colon form; nil when it is not a MAC.
    public static func normalize(_ text: String) -> String? {
        let hex = text.trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "").replacingOccurrences(of: ".", with: "")
            .lowercased()
        guard hex.count == 12, hex.allSatisfy({ $0.isHexDigit }) else { return nil }
        return stride(from: 0, to: 12, by: 2).map { i in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 2)])
        }.joined(separator: ":")
    }

    /// 6 x 0xFF followed by the MAC 16 times. `mac` must come from `normalize`.
    public static func magicPacket(_ mac: String) -> Data? {
        let bytes = mac.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard bytes.count == 6 else { return nil }
        return Data(repeating: 0xFF, count: 6) + Data((0..<16).flatMap { _ in bytes })
    }

    public struct SendFailed: Error {}

    /// Blocking and quick; call off the main thread.
    public static func send(_ mac: String) throws {
        guard let packet = magicPacket(mac) else { throw SendFailed() }
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw SendFailed() }
        defer { close(fd) }
        var on: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw SendFailed() }
        // iOS often drops the limited broadcast (255.255.255.255), so also target each Wi-Fi/Ethernet subnet's directed broadcast.
        var targets = [in_addr(s_addr: INADDR_BROADCAST.bigEndian)]
        targets += directedBroadcasts()
        var delivered = false
        for target in targets {
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr = target
            let sent = packet.withUnsafeBytes { p in
                withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, p.baseAddress, p.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent == packet.count { delivered = true }
        }
        guard delivered else { throw SendFailed() }
    }

    /// Broadcast addresses of the up, non-loopback, non-cellular IPv4 interfaces.
    static func directedBroadcasts() -> [in_addr] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var out: [in_addr] = []
        for ifa in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(ifa.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_BROADCAST != 0, flags & IFF_LOOPBACK == 0,
                  let a = ifa.pointee.ifa_addr, a.pointee.sa_family == sa_family_t(AF_INET),
                  let m = ifa.pointee.ifa_netmask,
                  !String(cString: ifa.pointee.ifa_name).hasPrefix("pdp_ip") else { continue }
            let ip = a.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let mask = m.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            out.append(in_addr(s_addr: ip | ~mask))
        }
        return out
    }
}
