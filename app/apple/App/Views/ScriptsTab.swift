import ServerHandsKit
import SwiftUI

struct ScriptsTab: View {
    @EnvironmentObject private var model: AppModel
    let onRun: (ScriptView) -> Void

    var body: some View {
        let scripts = model.scripts
        Page(title: "Scripts") {
            StatusStrip()
            if let scripts, !scripts.unlocked {
                Panel {
                    HStack(spacing: 12) {
                        Image(systemName: "lock.fill").foregroundStyle(.red).font(.title3)
                        Text("Drives are locked. Scripts that need the data are refused until they are unlocked.")
                    }
                }
            }
            if scripts == nil || scripts!.scripts.isEmpty {
                Panel {
                    Text(scripts == nil ? "Not loaded yet." : "No scripts configured.").font(.headline)
                    Text(scripts == nil ? "Check the connection to load the server's scripts." : "Add [[script]] entries to /etc/server-hands/config.toml on the server.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Check") { model.refresh() }.buttonStyle(.capsule).disabled(model.busy != nil)
                }
            } else if let scripts {
                ForEach(scripts.scripts) { s in ScriptItem(s: s, enabled: model.busy == nil) { onRun(s) } }
            }
        }
        .refreshable { model.refresh() }
    }
}

private struct ScriptItem: View {
    let s: ScriptView
    let enabled: Bool
    let onRun: () -> Void

    var body: some View {
        let tint: Color = switch s.state {
        case "failed": .red
        case "running", "queued": .teal
        default: .accentColor
        }
        Panel {
            HStack(spacing: 12) {
                IconBadge(symbol: "terminal", tint: tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(s.label).font(.headline)
                    let state = switch s.state {
                    case "idle": "not run yet"
                    case "queued": "waiting"
                    case "running": "running"
                    case "ok": "finished"
                    default: "failed"
                    }
                    Text((s.mode == "auto" ? "Runs automatically" : "Manual") + " · " + state)
                        .font(.footnote).foregroundStyle(s.state == "failed" ? Color.red : Color.secondary)
                    if s.biometricProtection { Pill("Biometric", .accentColor).padding(.top, 4) }
                    else if s.requiresConfirmation { Pill("Asks first", .gray).padding(.top, 4) }
                }
                Spacer()
                Button(action: onRun) { Label(s.state == "failed" ? "Retry" : "Run", systemImage: "play.fill") }
                    .buttonStyle(.capsule)
                    .disabled(!enabled || s.busy)
            }
        }
    }
}
