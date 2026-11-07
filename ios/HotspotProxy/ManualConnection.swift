import Foundation

/// The values that another device needs to use this proxy directly.
///
/// Pairing hands these values to a HotspotShade target device. A different
/// SOCKS5 client, such as the target command-line adapter, has no pairing
/// channel. The person reads the values here and enters them there.
///
/// The type holds the address and the port only. It never holds the source
/// token. The token stays in the Keychain and appears only through the timed
/// reveal in Settings. The copy text names the token field but does not
/// include a token or any other secret.
struct ManualConnection: Equatable {
    /// The SOCKS5 user name. It is not secret, and every client must send it.
    static let username = ProxyProtocol.socksUsername

    /// The hotspot address the listener uses, or nil when the app has none.
    let address: String?
    /// The configured proxy port, or nil when the setting is not a valid port.
    let port: UInt16?
    /// True only after the proxy listener reported Listening.
    let running: Bool
    /// True while a start is still in progress.
    let starting: Bool

    /// The plain port line.
    var portText: String {
        guard let port, ProxyPort.isValid(port) else {
            return "No valid port. Set one in Advanced."
        }
        return String(port)
    }

    /// The plain state line for the person. It says when a connection can work.
    var stateText: String {
        guard address != nil else {
            return "The app has no hotspot address yet. A connection will not work."
        }
        guard let port, ProxyPort.isValid(port) else {
            return "The app has no valid proxy port yet. A connection will not work."
        }
        return running
            ? "The proxy is on. Another device can connect now."
            : (starting
               ? "The proxy is starting. Wait until it reports On."
               : "Start the proxy before another device connects.")
    }

    /// True when there is enough information to configure another client.
    var isUsable: Bool {
        address != nil && port.map(ProxyPort.isValid) == true
    }

    /// The text that the Copy connection details action writes. It holds no
    /// token and no other secret. It is nil when the values are not usable.
    var copyText: String? {
        guard let address, let port, ProxyPort.isValid(port) else { return nil }
        return """
        HotspotShade SOCKS5 proxy
        Server: \(address):\(port)
        Username: \(Self.username)
        Password: the source token. Show it in HotspotShade Settings, Advanced.
        Use remote DNS, for example a socks5h proxy URL, so names resolve on the source device.
        """
    }
}
