import SwiftUI

struct PairScreen: View {
    @EnvironmentObject private var model: AppModel
    @State private var pasted = ""
    @State private var scanning = false

    var body: some View {
        Page(title: "Server Hands") {
            StatusStrip()
            Panel {
                Text("Pair with your server").font(.headline)
                Text("On the server run: sudo handsctl pair").font(.footnote).foregroundStyle(.secondary)
                #if os(iOS)
                Button("Scan QR code") { scanning = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.busy != nil)
                #endif
                TextField("or paste the hands:// link", text: $pasted)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    #endif
                Button("Pair") { model.pair(pasted); pasted = "" }
                    .buttonStyle(.bordered)
                    .disabled(model.busy != nil || pasted.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        #if os(iOS)
        .fullScreenCover(isPresented: $scanning) {
            QRScannerScreen { code in
                scanning = false
                if let code { model.pair(code) }
            }
        }
        #endif
    }
}
