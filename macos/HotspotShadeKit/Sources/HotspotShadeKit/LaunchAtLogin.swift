import Foundation
#if canImport(ServiceManagement)
import ServiceManagement
#endif

// The launch at login setting. An unsigned app cannot register, so the
// Settings window shows a note in that case.
public enum LaunchAtLogin {
    public static var isAvailable: Bool {
        #if canImport(ServiceManagement)
        return SMAppService.mainApp.status != .notFound
        #else
        return false
        #endif
    }

    public static var isEnabled: Bool {
        #if canImport(ServiceManagement)
        return SMAppService.mainApp.status == .enabled
        #else
        return false
        #endif
    }

    public static func set(_ enabled: Bool) {
        #if canImport(ServiceManagement)
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            // The Settings window reads the real state after this call.
        }
        #endif
    }
}
