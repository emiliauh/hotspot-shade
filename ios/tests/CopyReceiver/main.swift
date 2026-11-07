import UIKit
import CryptoKit

// Simulator-only receiver for a manual cross-app paste check. It never displays
// or logs the pasted value. This fixture is not part of HotspotShade.
final class ReceiverController: UIViewController {
    private let result = UILabel()
    private var baseline: SHA256.Digest?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let capture = UIButton(type: .system)
        capture.setTitle("Record first paste", for: .normal)
        capture.addTarget(self, action: #selector(recordPaste), for: .touchUpInside)
        let compare = UIButton(type: .system)
        compare.setTitle("Compare later paste", for: .normal)
        compare.addTarget(self, action: #selector(comparePaste), for: .touchUpInside)
        result.text = "Waiting"
        let stack = UIStackView(arrangedSubviews: [capture, compare, result])
        stack.axis = .vertical
        stack.spacing = 24
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }

    @objc private func recordPaste() {
        guard let value = UIPasteboard.general.string, !value.isEmpty else {
            baseline = nil
            result.text = "No value received"
            return
        }
        baseline = SHA256.hash(data: Data(value.utf8))
        result.text = "First value recorded"
    }

    @objc private func comparePaste() {
        guard let baseline = baseline else {
            result.text = "Record the first value"
            return
        }
        guard let value = UIPasteboard.general.string, !value.isEmpty else {
            result.text = "No value received"
            return
        }
        result.text = SHA256.hash(data: Data(value.utf8)) == baseline
            ? "Values match" : "Values differ"
    }
}

@objc(CopyReceiverSceneDelegate)
final class ReceiverSceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = ReceiverController()
        window.makeKeyAndVisible()
        self.window = window
    }
}

@main final class ReceiverApp: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Default", sessionRole: connectingSceneSession.role)
        configuration.delegateClass = ReceiverSceneDelegate.self
        return configuration
    }
}
