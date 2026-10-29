import SwiftUI

extension Color {
    /// Card background that follows the system appearance on iOS and macOS.
    static var panelBackground: Color {
        #if os(iOS)
        Color(uiColor: .secondarySystemBackground)
        #else
        Color(nsColor: .controlBackgroundColor)
        #endif
    }
}

/// A rounded card.
struct Panel<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.panelBackground, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

struct Pill: View {
    let text: String
    let tint: Color

    init(_ text: String, _ tint: Color) { self.text = text; self.tint = tint }

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 10).padding(.vertical, 4)
            .overlay(Capsule().strokeBorder(tint.opacity(0.6), lineWidth: 1))
    }
}

struct IconBadge: View {
    let symbol: String
    let tint: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 18, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: 40, height: 40)
            .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .accessibilityHidden(true)
    }
}

struct UsageBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary)
                Capsule().fill(fraction > 0.9 ? Color.red : fraction > 0.75 ? Color.pink : Color.accentColor)
                    .frame(width: max(geo.size.width * fraction, fraction > 0 ? 6 : 0))
            }
        }
        .frame(height: 8)
        .accessibilityElement()
        .accessibilityLabel("Usage")
        .accessibilityValue("\(Int(fraction * 100)) percent")
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View { Text(text).font(.title3.weight(.semibold)).padding(.top, 4) }
}

/// Scrolling column with a readable width on iPad and Mac.
struct Page<Content: View>: View {
    @EnvironmentObject private var model: AppModel
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(title).font(.largeTitle.weight(.bold)).padding(.top, 8)
                content
            }
            .frame(maxWidth: 640, alignment: .leading)
            .padding(.horizontal, 16).padding(.bottom, 24)
            .frame(maxWidth: .infinity)
        }
        .busyBubble(model.busy)
        .animation(.easeInOut(duration: 0.2), value: model.busy)
    }
}

/// What is going on right now: the pairing code and the last message.
struct StatusStrip: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let sas = model.sas {
            Panel {
                Text("Confirm on the server console that this code matches:")
                Text(sas).font(.system(size: 40, design: .monospaced))
                Text("Pairing continues once the operator confirms.").font(.footnote).foregroundStyle(.secondary)
            }
        }
        if let message = model.message {
            Text(message).foregroundStyle(Color.accentColor).textSelection(.enabled)
        }
    }
}

private extension View {
    /// iOS: an inset, so the list can always scroll clear of the bubble. macOS: an overlay, so the list is not pushed down.
    @ViewBuilder func busyBubble(_ label: String?) -> some View {
        #if os(iOS)
        safeAreaInset(edge: .bottom) { bubble(label) }
        #else
        overlay(alignment: .top) { bubble(label) }
        #endif
    }

    @ViewBuilder private func bubble(_ label: String?) -> some View {
        if let label { BusyBubble(label: label).transition(.move(edge: BusyBubble.edge == .top ? .top : .bottom).combined(with: .opacity)) }
    }
}

/// A floating rounded status bubble: above the tab bar on iOS, below it on macOS where the tabs are on top.
struct BusyBubble: View {
    let label: String

    #if os(iOS)
    static let edge: VerticalEdge = .bottom
    #else
    static let edge: VerticalEdge = .top
    #endif

    var body: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            Text(label).font(.subheadline)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(.quaternary))
        .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
        .padding(.horizontal, 16).padding(.vertical, 8)
        .frame(maxWidth: .infinity)
    }
}

/// Capsule button that looks the same on iOS and macOS (the stock `.bordered` is a plain rounded rect on the Mac).
/// `prominent` fills with the accent colour; `large` is a full-width, taller button.
struct CapsuleButtonStyle: ButtonStyle {
    var prominent = false
    var large = false
    @Environment(\.isEnabled) private var enabled
    @Environment(\.colorScheme) private var scheme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(large ? .headline : .subheadline.weight(.semibold))
            .foregroundStyle(prominent ? (scheme == .dark ? Color.black : Color.white) : Color.accentColor)
            .padding(.horizontal, large ? 24 : 14).padding(.vertical, large ? 14 : 7)
            .frame(maxWidth: large ? .infinity : nil)
            .background(prominent ? Color.accentColor : Color.accentColor.opacity(0.14), in: Capsule())
            .opacity(enabled ? (configuration.isPressed ? 0.7 : 1) : 0.4)
            .contentShape(Capsule())
    }
}

extension ButtonStyle where Self == CapsuleButtonStyle {
    static var capsule: CapsuleButtonStyle { CapsuleButtonStyle() }
    static var capsuleProminent: CapsuleButtonStyle { CapsuleButtonStyle(prominent: true) }
    static var capsuleLarge: CapsuleButtonStyle { CapsuleButtonStyle(large: true) }
    static var capsuleLargeProminent: CapsuleButtonStyle { CapsuleButtonStyle(prominent: true, large: true) }
}
