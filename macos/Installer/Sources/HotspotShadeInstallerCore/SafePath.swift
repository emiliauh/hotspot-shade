import Foundation

// A path that the coordinator may join to one target root. Every component is
// checked before a system call. The coordinator never uses a path from a
// journal, a manifest, or a command line as an absolute filesystem path. The
// fixed layout is expressed as relative components and opened with openat
// against a held descriptor.
public enum SafeRelativePath {
    public static let maximumBytes = 4096
    public static let maximumComponentBytes = 255

    // A safe relative path has no empty component, no "." or "..", no leading
    // slash, no NUL, and only printable ASCII that cannot change a shell word.
    // The space is allowed because the install location contains
    // "Application Support".
    public static func components(_ path: String) -> [String]? {
        guard !path.isEmpty,
              path.utf8.count <= maximumBytes,
              !path.contains("\0"),
              !path.hasPrefix("/")
        else { return nil }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty else { return nil }
        var result: [String] = []
        result.reserveCapacity(parts.count)
        for part in parts {
            let component = String(part)
            guard !component.isEmpty,
                  component != ".",
                  component != "..",
                  component.utf8.count <= maximumComponentBytes,
                  !component.hasPrefix(" "),
                  !component.hasSuffix(" ")
            else { return nil }
            for byte in component.utf8 {
                let allowed = (byte >= 0x41 && byte <= 0x5A)      // A-Z
                    || (byte >= 0x61 && byte <= 0x7A)             // a-z
                    || (byte >= 0x30 && byte <= 0x39)             // 0-9
                    || byte == 0x20                               // space
                    || byte == 0x2E                               // .
                    || byte == 0x5F                               // _
                    || byte == 0x2D                               // -
                guard allowed else { return nil }
            }
            result.append(component)
        }
        return result
    }

    public static func isValid(_ path: String) -> Bool {
        components(path) != nil
    }

    // Join for a read-only signature check or an error message. File and
    // directory operations use openat against descriptors instead.
    public static func join(root: String, relative: String) -> String? {
        guard let parts = components(relative) else { return nil }
        let base = root.hasSuffix("/") ? String(root.dropLast()) : root
        return base + "/" + parts.joined(separator: "/")
    }
}
