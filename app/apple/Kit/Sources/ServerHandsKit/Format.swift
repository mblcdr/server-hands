import Foundation

/// Decimal units, like drive makers and `df -H`: 4 TB means 4 * 10^12 bytes.
public func formatBytes(_ bytes: Int64) -> String {
    if bytes <= 0 { return "0 B" }
    let units = ["B", "kB", "MB", "GB", "TB", "PB"]
    var v = Double(bytes)
    var i = 0
    while v >= 1000 && i < units.count - 1 { v /= 1000; i += 1 }
    if i == 0 { return "\(bytes) B" }
    return String(format: v < 10 ? "%.1f %@" : "%.0f %@", v, units[i])
}

/// "3d 4h", "4h 12m", "12m", "45s".
public func formatUptime(_ secs: Int64) -> String {
    let d = secs / 86_400, h = secs % 86_400 / 3_600, m = secs % 3_600 / 60
    if d > 0 { return "\(d)d \(h)h" }
    if h > 0 { return "\(h)h \(m)m" }
    if m > 0 { return "\(m)m" }
    return "\(max(secs, 0))s"
}

public func fraction(_ part: Int64, _ whole: Int64) -> Double {
    whole <= 0 ? 0 : min(max(Double(part) / Double(whole), 0), 1)
}

public func percent(_ f: Double) -> String { "\(Int(f * 100))%" }
