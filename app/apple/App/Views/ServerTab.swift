import ServerHandsKit
import SwiftUI

struct ServerTab: View {
    @EnvironmentObject private var model: AppModel
    let onEnroll: (RequestView) -> Void
    let onWake: () -> Void

    var body: some View {
        let idle = model.busy == nil
        let enrolled = Set(model.pairing?.drives.map(\.uuid) ?? [])
        Page(title: "Server Hands") {
            StatusStrip()
            if let pairing = model.pairing { ConnectionPanel(pairing: pairing, idle: idle, onWake: onWake) }
            if let s = model.status { MachinePanel(s: s) }

            // Only while connected, and only when something is waiting or a drive is still locked.
            let drives = model.status?.drives
            let stillLocked = drives.map { d in d.isEmpty || !d.allSatisfy { $0.state == "mounted" || $0.state == "open" } } ?? false
            if model.connected == true && (!model.requests.isEmpty || stillLocked) {
                HStack {
                    SectionTitle("Unlock requests")
                    Spacer()
                    Button("Check") { model.refresh() }.buttonStyle(.capsule).disabled(!idle)
                }
                if model.requests.isEmpty {
                    Text("No drives waiting to be unlocked.").foregroundStyle(.secondary).padding(.leading, 4)
                }
                ForEach(model.requests) { r in
                    ForEach(r.drives, id: \.luksUuid) { d in RequestDriveItem(d: d, saved: enrolled.contains(d.luksUuid)) }
                    VStack(spacing: 10) {
                        if r.drives.contains(where: { enrolled.contains($0.luksUuid) }) {
                            Button("Unlock") { model.unlock(r) }.buttonStyle(.capsuleLargeProminent).disabled(!idle)
                        }
                        if r.drives.contains(where: { !enrolled.contains($0.luksUuid) }) {
                            Button("Save passphrases") { onEnroll(r) }.buttonStyle(.capsuleLarge).disabled(!idle)
                        }
                    }
                    .frame(maxWidth: 420).frame(maxWidth: .infinity)
                }
            }

            let unlocked = (model.status?.drives ?? []).filter { $0.state == "mounted" || $0.state == "open" }
            if !unlocked.isEmpty {
                SectionTitle("Drives")
                ForEach(unlocked) { DriveUsageItem(d: $0) }
            }
            let pools = model.status?.pools ?? []
            if !pools.isEmpty {
                SectionTitle(pools.count == 1 ? "Pool" : "Pools")
                ForEach(pools) { PoolItem(p: $0) }
            }
        }
        .refreshable { model.refresh() }
    }
}

/// Server status; tap to show the pairing details and the forget button.
private struct ConnectionPanel: View {
    @EnvironmentObject private var model: AppModel
    let pairing: PairingRecord
    let idle: Bool
    let onWake: () -> Void
    @State private var expanded = false
    @State private var confirmingForget = false
    @State private var editing = false

    var body: some View {
        let tint: Color = model.connected == false ? .red : .accentColor
        Panel {
            HStack(spacing: 12) {
                IconBadge(symbol: "server.rack", tint: tint)
                VStack(alignment: .leading) {
                    let host = model.status?.hostname ?? ""
                    Text(host.isEmpty ? pairing.host : host).font(.headline)
                    Text("\(pairing.host):\(pairing.port)").font(.footnote).foregroundStyle(.secondary)
                }
                Spacer()
                switch model.connected {
                case true?: Pill("Connected", .accentColor)
                case false?: Pill("Offline", .red)
                case nil: Pill(model.busy != nil ? "Connecting" : "Not checked", .gray)
                }
            }
            if model.connected == false {
                Button { onWake() } label: { Text("Wake (Wake-on-LAN)").frame(maxWidth: .infinity) }
                    .buttonStyle(.bordered).disabled(!idle)
            }
            if expanded {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Key fingerprint").font(.caption).foregroundStyle(.secondary).padding(.top, 8)
                    Text(pairing.fingerprintText).font(.footnote.monospaced()).textSelection(.enabled)
                    Text("This device: \(pairing.deviceName)").font(.footnote)
                    Text("Saved passphrases: \(pairing.drives.isEmpty ? "none" : pairing.drives.map(\.label).joined(separator: ", "))").font(.footnote)
                    if let mac = pairing.mac { Text("MAC address: \(mac)").font(.footnote) }
                    Button { editing = true } label: { Text("Edit server details").frame(maxWidth: .infinity) }
                        .buttonStyle(.bordered).disabled(!idle).padding(.top, 8)
                    Button(role: .destructive) { confirmingForget = true } label: { Text("Forget this server").frame(maxWidth: .infinity) }
                        .buttonStyle(.borderedProminent).tint(.red).disabled(!idle).padding(.top, 2)
                }
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { withAnimation { expanded.toggle() } }
        .sheet(isPresented: $editing) {
            EditServerSheet(pairing: pairing) { model.updateServer(host: $0, port: $1, mac: $2) }
        }
        .confirmationDialog("Forget this server?", isPresented: $confirmingForget, titleVisibility: .visible) {
            Button("Forget", role: .destructive) { model.forget() }
        } message: {
            Text("The pairing, the device key and the saved passphrases are deleted from this device.")
        }
    }
}

private extension PairingRecord {
    var fingerprintText: String { (try? pin.fingerprint) ?? "unknown" }
}

private struct MachinePanel: View {
    let s: ServerStatus

    var body: some View {
        Panel {
            HStack {
                Text("Up \(formatUptime(s.uptimeSecs))").font(.subheadline.weight(.semibold))
                Spacer()
                Text(s.kernel).font(.footnote).foregroundStyle(.secondary)
            }
            Meter(title: "CPU", fraction: s.cpuPercent / 100, detail: "\(Int(s.cpuPercent))% of \(s.cpus) \(s.cpus == 1 ? "core" : "cores")")
            let memUsed = max(s.memTotal - s.memAvailable, 0)
            Meter(title: "Memory", fraction: fraction(memUsed, s.memTotal), detail: "\(formatBytes(memUsed)) of \(formatBytes(s.memTotal))")
            if s.swapTotal > 0 {
                let swapUsed = max(s.swapTotal - s.swapFree, 0)
                Meter(title: "Swap", fraction: fraction(swapUsed, s.swapTotal), detail: "\(formatBytes(swapUsed)) of \(formatBytes(s.swapTotal))")
            }
            if s.load.count == 3 {
                Text("Load  " + s.load.map { String(format: "%.2f", $0) }.joined(separator: "  ")).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

private struct Meter: View {
    let title: String
    let fraction: Double
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.subheadline.weight(.medium))
                Spacer()
                Text(detail).font(.footnote).foregroundStyle(.secondary)
            }
            UsageBar(fraction: min(max(fraction, 0), 1))
        }
    }
}

/// One locked drive in an unlock request.
private struct RequestDriveItem: View {
    let d: DriveInfo
    let saved: Bool

    var body: some View {
        Panel {
            HStack(spacing: 12) {
                IconBadge(symbol: "internaldrive", tint: .brown)
                VStack(alignment: .leading, spacing: 2) {
                    Text(d.label).font(.headline)
                    Text(formatBytes(d.size)).font(.subheadline)
                    Text(d.luksUuid).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    Pill("Locked", .red)
                    Pill(saved ? "Passphrase saved" : "No passphrase", saved ? .accentColor : .gray)
                }
            }
        }
    }
}

/// An unlocked drive with how full it is.
private struct DriveUsageItem: View {
    let d: DriveStatus

    var body: some View {
        Panel {
            HStack(spacing: 12) {
                IconBadge(symbol: "internaldrive", tint: .accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(d.label).font(.headline)
                    Text(formatBytes(d.total > 0 ? d.total : d.size)).font(.subheadline)
                }
                Spacer()
                if d.state == "mounted" { Pill(percent(fraction(d.used, d.total)), .accentColor) } else { Pill("Not mounted", .gray) }
            }
            if d.state == "mounted" {
                UsageBar(fraction: fraction(d.used, d.total))
                Text("\(formatBytes(d.used)) used  ·  \(formatBytes(d.avail)) free").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

/// The merged pool (for example mergerfs).
private struct PoolItem: View {
    let p: PoolStatus

    var body: some View {
        Panel {
            HStack(spacing: 12) {
                IconBadge(symbol: "square.stack.3d.up", tint: .accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(p.name).font(.headline)
                    Text(p.mountPoint).font(.caption2.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                if p.mounted {
                    let kind = p.fstype.hasPrefix("fuse.") ? String(p.fstype.dropFirst(5)) : p.fstype
                    Pill(kind.isEmpty ? "pool" : kind, .accentColor)
                } else {
                    Pill("Not mounted", .gray)
                }
            }
            if p.mounted {
                Text(formatBytes(p.total)).font(.title2.weight(.semibold))
                UsageBar(fraction: fraction(p.used, p.total))
                Text("\(formatBytes(p.used)) used  ·  \(formatBytes(p.avail)) free  ·  \(percent(fraction(p.used, p.total)))").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}
