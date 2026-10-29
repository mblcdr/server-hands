#if os(iOS)
import AVFoundation
import SwiftUI

/// Full-screen camera view that returns the first QR code it sees. In-app scanning only: the `hands://` scheme is not registered as a deep link.
struct QRScannerScreen: View {
    let onResult: (String?) -> Void

    var body: some View {
        ZStack(alignment: .topTrailing) {
            QRScannerView(onCode: { onResult($0) }).ignoresSafeArea()
            VStack {
                Spacer()
                Text("Scan the QR from handsctl pair")
                    .padding(10).background(.thinMaterial, in: Capsule())
                    .padding(.bottom, 40)
            }
            .frame(maxWidth: .infinity)
            Button("Cancel") { onResult(nil) }
                .buttonStyle(.borderedProminent).padding()
        }
    }
}

private struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_ vc: ScannerController, context: Context) {}
}

private final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var done = false

    private var configured = false
    private let deniedView = UIStackView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupDeniedView()
        NotificationCenter.default.addObserver(self, selector: #selector(checkAccess), name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        checkAccess()
    }

    /// Re-evaluated on appear and whenever the app becomes active, so returning from Settings picks up a changed permission.
    @objc private func checkAccess() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            deniedView.isHidden = true
            start()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { _ in DispatchQueue.main.async { self.checkAccess() } }
        default:
            stop()
            deniedView.isHidden = false
        }
    }

    private func setupDeniedView() {
        let label = UILabel()
        label.text = "Camera access is needed to scan the pairing QR code. Enable it in Settings."
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        var config = UIButton.Configuration.borderedProminent()
        config.title = "Open Settings"
        let button = UIButton(configuration: config, primaryAction: UIAction { _ in
            if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
        })
        deniedView.axis = .vertical
        deniedView.spacing = 16
        deniedView.alignment = .center
        deniedView.isHidden = true
        deniedView.addArrangedSubview(label)
        deniedView.addArrangedSubview(button)
        deniedView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(deniedView)
        NSLayoutConstraint.activate([
            deniedView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            deniedView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            deniedView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
        ])
    }

    private func configure() -> Bool {
        if configured { return true }
        guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return false }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return false }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.insertSublayer(layer, at: 0)
        preview = layer
        configured = true
        updateOrientation()
        return true
    }

    private func start() {
        guard configure(), !session.isRunning else { return }
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    private func stop() {
        guard session.isRunning else { return }
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
    }

    deinit { NotificationCenter.default.removeObserver(self) }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
        updateOrientation()
    }

    private func updateOrientation() {
        guard let c = preview?.connection else { return }
        let o = view.window?.windowScene?.interfaceOrientation ?? .portrait
        if #available(iOS 17.0, *) {
            if c.isVideoRotationAngleSupported(0) { c.videoRotationAngle = Self.angle(o) }
        } else if c.isVideoOrientationSupported, let v = AVCaptureVideoOrientation(rawValue: o.rawValue) {
            c.videoOrientation = v
        }
    }

    private static func angle(_ o: UIInterfaceOrientation) -> CGFloat {
        switch o {
        case .landscapeLeft: 180
        case .landscapeRight: 0
        case .portraitUpsideDown: 270
        default: 90
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        stop()
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !done, let text = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        done = true
        onCode?(text)
    }
}
#endif
