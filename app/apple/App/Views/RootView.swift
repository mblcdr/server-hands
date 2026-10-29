import ServerHandsKit
import SwiftUI

@MainActor
struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var phase
    @State private var tab = Tab.server
    @State private var askingMac = false
    @State private var confirming: ScriptView?
    @State private var enrolling: RequestView?

    enum Tab: Hashable { case server, scripts }

    var body: some View {
        VStack(spacing: 0) {
            if model.pairing == nil {
                PairScreen()
            } else {
                TabView(selection: $tab) {
                    ServerTab(onEnroll: { enrolling = $0 }, onWake: { if model.pairing?.mac == nil { askingMac = true } else { model.wake() } })
                        .tabItem { Label("Server", systemImage: "server.rack") }
                        .tag(Tab.server)
                    ScriptsTab(onRun: { s in
                        // With biometric protection the biometric prompt is the confirmation: no extra dialog.
                        if s.requiresConfirmation && !s.biometricProtection { confirming = s } else { model.runScript(s) }
                    })
                    .tabItem { Label("Scripts", systemImage: "terminal") }
                    .tag(Tab.scripts)
                }
            }
        }
        // Reconnect (or confirm the connection) and keep the server status fresh while the app is in the foreground.
        .onAppear { if phase == .active { model.onResume() } }
        .onChange(of: phase) { p in
            if p == .active { model.onResume() } else { model.onPause() }
        }
        .sheet(isPresented: $askingMac) {
            MacSheet { askingMac = false; model.wake(newMac: $0) }
        }
        .sheet(item: $enrolling) { req in
            EnrollSheet(drives: missingDrives(req)) { map in
                enrolling = nil
                model.enroll(drives: req.drives, passphrases: map)
            }
        }
        .alert("Run \(confirming?.label ?? "")?", isPresented: .init(get: { confirming != nil }, set: { if !$0 { confirming = nil } })) {
            Button("Run") { if let s = confirming { model.runScript(s) }; confirming = nil }
            Button("Cancel", role: .cancel) { confirming = nil }
        } message: {
            Text("This starts the script on \(model.pairing?.host ?? "the server") right away.")
        }
        .alert("Result", isPresented: .init(get: { !model.results.isEmpty }, set: { if !$0 { model.results = [] } })) {
            Button("OK") { model.results = [] }
        } message: {
            Text(model.results.map { r in
                let name = model.pairing?.drives.first { $0.uuid == r.luksUuid }?.label ?? r.luksUuid
                let outcome = switch r.result {
                case "ok": "unlocked"
                case "already_open": "already unlocked"
                case "bad_passphrase": "wrong passphrase"
                default: "failed"
                }
                return "\(name): \(outcome)"
            }.joined(separator: "\n"))
        }
    }

    private func missingDrives(_ req: RequestView) -> [DriveInfo] {
        let missing = req.drives.filter { d in model.pairing?.drives.contains { $0.uuid == d.luksUuid } != true }
        return missing.isEmpty ? req.drives : missing
    }
}
