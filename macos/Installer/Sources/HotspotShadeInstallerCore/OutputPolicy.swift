import Foundation
import Darwin

// Where the build may write. The build runs as the signed-in account and
// writes one new directory. It never writes a system path.
public enum OutputPolicy {
    static let deniedPrefixes = [
        "/System", "/Library", "/Applications", "/usr", "/bin", "/sbin", "/etc",
        "/private/etc", "/private/var/db", "/private/var/lib", "/private/var/root",
        "/private/var/run", "/dev", "/cores", "/opt",
    ]

    // Returns the resolved absolute path to create. The directory must not
    // exist, its parent must be a real directory, and the result must be
    // outside every denied prefix after symlinks resolve.
    public static func resolve(_ requested: String) throws -> String {
        guard requested.hasPrefix("/"), !requested.contains("\0") else {
            throw InstallerError.outputUnsafe("the path must be absolute")
        }
        let standardized = URL(fileURLWithPath: requested).standardizedFileURL.path
        let parent = (standardized as NSString).deletingLastPathComponent
        let name = (standardized as NSString).lastPathComponent
        guard !name.isEmpty, name != "/", name != ".", name != ".." else {
            throw InstallerError.outputUnsafe("the path has no directory name")
        }
        guard let resolvedParent = realpath(parent, nil) else {
            throw InstallerError.outputUnsafe("the parent directory does not exist")
        }
        defer { free(resolvedParent) }
        let parentPath = String(cString: resolvedParent)
        var status = stat()
        guard lstat(parentPath, &status) == 0, status.st_mode & S_IFMT == S_IFDIR else {
            throw InstallerError.outputUnsafe("the parent is not a directory")
        }
        guard status.st_mode & 0o022 == 0 || status.st_mode & S_ISVTX != 0 else {
            throw InstallerError.outputUnsafe("the parent is writable by other users")
        }
        let resolved = (parentPath as NSString).appendingPathComponent(name)
        for prefix in deniedPrefixes where resolved == prefix || resolved.hasPrefix(prefix + "/") {
            throw InstallerError.outputUnsafe("system path")
        }
        guard lstat(resolved, &status) != 0 else {
            throw InstallerError.outputUnsafe("the directory already exists")
        }
        return resolved
    }
}
