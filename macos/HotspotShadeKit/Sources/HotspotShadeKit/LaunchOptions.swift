import Foundation

// The start options for the app. A person starts demo mode with the --demo
// argument or with HS_DEMO=1 in the environment. The app then starts its own
// engine with --demo. No route and no real tunnel is used.
public struct LaunchOptions: Equatable {
    public var demo: Bool
    public init(demo: Bool) { self.demo = demo }
    public init(arguments: [String] = CommandLine.arguments, environment: [String: String] = ProcessInfo.processInfo.environment) {
        demo = arguments.contains("--demo") || environment["HS_DEMO"] == "1"
    }
}
