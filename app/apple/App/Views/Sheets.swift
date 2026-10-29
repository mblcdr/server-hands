import ServerHandsKit
import SwiftUI

struct MacSheet: View {
    let onSave: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var mac = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("MAC address", text: $mac, prompt: Text("aa:bb:cc:dd:ee:ff"))
                        .labelsHidden().multilineTextAlignment(.leading)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } header: {
                    Text("Server MAC address")
                } footer: {
                    Text("Wake-on-LAN needs the MAC address of the server's network card. It is saved on this device for next time. On the server: ip link")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Wake-on-LAN")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save and wake") { onSave(mac) }.disabled(WakeOnLan.normalize(mac) == nil)
                }
            }
        }
        .frame(minWidth: 360, minHeight: 240)
        .presentationDetents([.medium])
    }
}

struct EditServerSheet: View {
    let pairing: PairingRecord
    let onSave: (String, String, String) -> String?
    @Environment(\.dismiss) private var dismiss
    @State private var host: String
    @State private var port: String
    @State private var mac: String
    @State private var error: String?

    init(pairing: PairingRecord, onSave: @escaping (String, String, String) -> String?) {
        self.pairing = pairing; self.onSave = onSave
        _host = State(initialValue: pairing.host)
        _port = State(initialValue: String(pairing.port))
        _mac = State(initialValue: pairing.mac ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Address", text: $host, prompt: Text("Address")).labelsHidden().multilineTextAlignment(.leading).autocorrectionDisabled()
                    TextField("Port", text: $port, prompt: Text("Port")).labelsHidden().multilineTextAlignment(.leading)
                        #if os(iOS)
                        .keyboardType(.numberPad)
                        #endif
                } header: {
                    Text("Server")
                } footer: {
                    Text("The server is still verified by the key it was paired with.")
                }
                Section {
                    TextField("MAC address", text: $mac, prompt: Text("aa:bb:cc:dd:ee:ff")).labelsHidden().multilineTextAlignment(.leading).autocorrectionDisabled()
                } header: {
                    Text("Wake-on-LAN MAC address")
                } footer: {
                    Text("Leave empty to remove it.")
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
            }
            .formStyle(.grouped)
            .navigationTitle("Edit server")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { if let e = onSave(host, port, mac) { error = e } else { dismiss() } }
                }
            }
        }
        .frame(minWidth: 360, minHeight: 360)
    }
}

/// Passphrases are typed into secure fields and turned into byte buffers that are wiped after use.
struct EnrollSheet: View {
    let drives: [DriveInfo]
    let onSave: ([String: Data]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var values: [String: String] = [:]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(drives, id: \.luksUuid) { d in
                        SecureField(d.label, text: Binding(get: { values[d.luksUuid] ?? "" }, set: { values[d.luksUuid] = $0 }))
                            .textContentType(.password)
                    }
                } header: {
                    Text("Passphrases")
                } footer: {
                    Text("Use the phone passphrase from: sudo handsctl add-phone-key <uuid>")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Save passphrases")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { values = [:]; dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save with biometric") {
                        let map = values.compactMapValues { $0.isEmpty ? nil : Data($0.utf8) }
                        values = [:]
                        onSave(map)
                    }
                    .disabled(values.values.allSatisfy(\.isEmpty))
                }
            }
        }
        .frame(minWidth: 400, minHeight: 300)
    }
}
