import Foundation
import Darwin

// A snapshot of one filesystem object. The verifier never follows a final
// symlink and never trusts an owner or mode that the current process reports
// about itself.
public struct HelperFileIdentity: Equatable, Sendable {
    public let ownerIdentifier: UInt32
    public let groupIdentifier: UInt32
    public let mode: UInt16
    public let isRegularFile: Bool
    public let isDirectory: Bool
    public let isSymbolicLink: Bool

    public init(
        ownerIdentifier: UInt32,
        groupIdentifier: UInt32,
        mode: UInt16,
        isRegularFile: Bool,
        isDirectory: Bool,
        isSymbolicLink: Bool
    ) {
        self.ownerIdentifier = ownerIdentifier
        self.groupIdentifier = groupIdentifier
        self.mode = mode
        self.isRegularFile = isRegularFile
        self.isDirectory = isDirectory
        self.isSymbolicLink = isSymbolicLink
    }

    public var isGroupOrOtherWritable: Bool { mode & 0o022 != 0 }
    public var isOwnerExecutable: Bool { mode & 0o100 != 0 }
}

public protocol HelperFileInspecting: Sendable {
    func identity(atPath path: String) throws -> HelperFileIdentity
    func canonicalPath(_ path: String) throws -> String
    // A mode bit is not the whole permission story. An extended ACL can grant
    // write access to a user even when the mode says otherwise.
    func hasWriteACL(atPath path: String) throws -> Bool
}

public extension HelperFileInspecting {
    func hasWriteACL(atPath path: String) throws -> Bool { false }
}

public protocol HelperFileReading: Sendable {
    func readFile(atPath path: String, maximumBytes: Int) throws -> Data
}

public struct SystemHelperFileReader: HelperFileReading {
    public init() {}
    public func readFile(atPath path: String, maximumBytes: Int) throws -> Data {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
        guard data.count <= maximumBytes else { throw HelperTrustError.launchDaemonPlistUnsafe }
        return data
    }
}

public struct SystemHelperFileSystem: HelperFileInspecting {
    public init() {}

    public func identity(atPath path: String) throws -> HelperFileIdentity {
        var status = stat()
        guard lstat(path, &status) == 0 else { throw HelperTrustError.notInstalledPath }
        let type = status.st_mode & S_IFMT
        return HelperFileIdentity(
            ownerIdentifier: status.st_uid,
            groupIdentifier: status.st_gid,
            mode: UInt16(status.st_mode & 0o7777),
            isRegularFile: type == S_IFREG,
            isDirectory: type == S_IFDIR,
            isSymbolicLink: type == S_IFLNK
        )
    }

    public func canonicalPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw HelperTrustError.notInstalledPath }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    // Reject any allow entry that grants a write-like right. We do not try to
    // resolve the qualifier GUID to a user here. An installed helper and its
    // directories have no extended ACL in the normal package. Any allow ACL
    // that can write is treated as unsafe rather than guessed at.
    public func hasWriteACL(atPath path: String) throws -> Bool {
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return false }
            throw HelperTrustError.aclUnavailable
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var index = ACL_FIRST_ENTRY
        while acl_get_entry(acl, Int32(index.rawValue), &entry) == 0, let entry {
            var tag = ACL_UNDEFINED_TAG
            if acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_ALLOW {
                var permissions: acl_permset_t?
                if acl_get_permset(entry, &permissions) == 0, let permissions {
                    for permission in [
                        ACL_WRITE_DATA,
                        ACL_DELETE,
                        ACL_APPEND_DATA,
                        ACL_DELETE_CHILD,
                        ACL_WRITE_ATTRIBUTES,
                        ACL_WRITE_EXTATTRIBUTES,
                        ACL_WRITE_SECURITY,
                        ACL_CHANGE_OWNER,
                    ] where acl_get_perm_np(permissions, permission) == 1 {
                        return true
                    }
                }
            }
            index = ACL_NEXT_ENTRY
        }
        return false
    }
}

public enum HelperInstallLayout: Equatable, Sendable {
    // The preferred production layout. A root-owned package writes the helper
    // and its launch daemon plist, and no user account can replace them.
    case rootOwnedCopy
    // The signed app bundle layout. The app and every parent must still be
    // root-owned and free of group or other write permission. A stock
    // /Applications folder is owned by root but writable by the admin group,
    // so this layout fails closed there.
    case signedAppBundle(appBundlePath: String)
}

public struct HelperInstallPolicy: Sendable {
    public let layout: HelperInstallLayout
    public let helperPath: String
    public let launchDaemonPlistPath: String?
    public let expectedTeamIdentifier: String
    public let helperIdentifier: String
    public let appIdentifier: String
    public let trustedExecutableRoot: String

    public init(
        layout: HelperInstallLayout,
        helperPath: String,
        launchDaemonPlistPath: String?,
        expectedTeamIdentifier: String,
        helperIdentifier: String = HelperRequirement.helperIdentifier,
        appIdentifier: String = HelperRequirement.appIdentifier,
        trustedExecutableRoot: String = HelperRequirement.helperInstallRoot
    ) {
        self.layout = layout
        self.helperPath = helperPath
        self.launchDaemonPlistPath = launchDaemonPlistPath
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.helperIdentifier = helperIdentifier
        self.appIdentifier = appIdentifier
        self.trustedExecutableRoot = trustedExecutableRoot
    }
}

public struct VerifiedHelperInstall: Equatable, Sendable {
    public let helperPath: String
    public let teamIdentifier: String
    public let layout: HelperInstallLayout
}

public extension HelperInstallPolicy {
    // Read the expected team from the running app's own signature. An unsigned
    // or ad-hoc app has no team and cannot use a protected helper. Do not take
    // the team from a plist, an environment variable, or a request.
    static func developerTeamIdentifier(
        bundlePath: String = Bundle.main.bundlePath,
        signatures: HelperCodeSignatureChecking = SecurityHelperCodeSignatureChecker()
    ) throws -> String {
        let info = try signatures.signingInfo(atPath: bundlePath)
        guard info.isProtectedIdentity,
              info.identifier == HelperRequirement.appIdentifier,
              let team = info.teamIdentifier
        else {
            throw HelperTrustError.missingSigningIdentity
        }
        try signatures.verifyStaticCode(
            atPath: bundlePath,
            requirement: HelperRequirement.make(
                identifier: HelperRequirement.appIdentifier,
                teamIdentifier: team
            )
        )
        return team
    }
}

public final class HelperInstallVerifier: Sendable {
    private let files: HelperFileInspecting
    private let signatures: HelperCodeSignatureChecking
    private let reader: HelperFileReading
    private let policy: HelperInstallPolicy

    public init(
        policy: HelperInstallPolicy,
        files: HelperFileInspecting = SystemHelperFileSystem(),
        signatures: HelperCodeSignatureChecking = SecurityHelperCodeSignatureChecker(),
        reader: HelperFileReading = SystemHelperFileReader()
    ) {
        self.policy = policy
        self.files = files
        self.signatures = signatures
        self.reader = reader
    }

    // This is the only entry point. There is no allow-unsigned or allow-user
    // owned switch. A caller that cannot provide a Developer ID team identifier
    // must show a plain unavailable state and must not elevate.
    public func verify() throws -> VerifiedHelperInstall {
        guard HelperRequirement.isValidTeamIdentifier(policy.expectedTeamIdentifier),
              HelperRequirement.isValidIdentifier(policy.helperIdentifier),
              HelperRequirement.isValidIdentifier(policy.appIdentifier)
        else {
            throw HelperTrustError.invalidSigningPolicy
        }
        let canonicalHelper = try canonical(path: policy.helperPath)
        switch policy.layout {
        case .rootOwnedCopy:
            try verifyRootOwnedCopy(canonicalHelper: canonicalHelper)
        case .signedAppBundle(let appPath):
            try verifySignedAppBundle(appBundlePath: appPath, canonicalHelper: canonicalHelper)
        }
        return VerifiedHelperInstall(
            helperPath: canonicalHelper,
            teamIdentifier: policy.expectedTeamIdentifier,
            layout: policy.layout
        )
    }

    private func verifyRootOwnedCopy(canonicalHelper: String) throws {
        let root = try canonical(path: policy.trustedExecutableRoot)
        guard root == policy.trustedExecutableRoot,
              canonicalHelper.hasPrefix(root + "/")
        else {
            throw HelperTrustError.unsafeInstallRoot
        }
        try verifyProtectedDirectory(root)
        try verifyProtectedDirectory(parent(of: root))
        try verifyProtectedDirectory("/")
        try verifyProtectedChain(from: canonicalHelper, through: root)
        try verifyProtectedExecutable(canonicalHelper, identifier: policy.helperIdentifier)
        // A root-owned copy without its launch daemon file has no on-demand
        // launch path. Treat a missing plist as an incomplete install instead
        // of silently trusting the executable alone.
        guard let plist = policy.launchDaemonPlistPath else {
            throw HelperTrustError.launchDaemonPlistMissing
        }
        try verifyLaunchDaemonPlist(plist, helperPath: canonicalHelper)
    }

    private func verifySignedAppBundle(appBundlePath: String, canonicalHelper: String) throws {
        let app = try canonical(path: appBundlePath)
        guard app.hasPrefix("/Applications/") || app.hasPrefix("/System/Applications/") else {
            throw HelperTrustError.bundleOutsideApplications
        }
        guard canonicalHelper.hasPrefix(app + "/") else { throw HelperTrustError.helperOutsideBundle }
        // A stock /Applications is group writable by admin. That is not a
        // trust boundary for a user process, so this layout is rejected there.
        try verifyProtectedAppBundle(app)
        try verifyProtectedDirectory(app)
        var current = app
        while current != "/" {
            let parent = parent(of: current)
            try verifyProtectedDirectory(parent)
            current = parent
        }
        try verifyProtectedChain(from: canonicalHelper, through: app)
        try verifyProtectedExecutable(
            canonicalHelper,
            identifier: policy.helperIdentifier,
            requireWheel: false
        )
        if let plist = policy.launchDaemonPlistPath {
            try verifyLaunchDaemonPlist(plist, helperPath: canonicalHelper)
        }
    }

    private func verifyProtectedExecutable(
        _ path: String,
        identifier: String,
        requireWheel: Bool = true
    ) throws {
        let identity = try files.identity(atPath: path)
        guard identity.isRegularFile, !identity.isSymbolicLink else {
            throw HelperTrustError.executableNotRegularFile
        }
        guard identity.ownerIdentifier == 0 else {
            throw HelperTrustError.executableNotOwnedByRoot
        }
        if requireWheel, identity.groupIdentifier != 0 {
            throw HelperTrustError.executableNotOwnedByRoot
        }
        guard !identity.isGroupOrOtherWritable else { throw HelperTrustError.executableWritable }
        guard try !files.hasWriteACL(atPath: path) else { throw HelperTrustError.executableWritable }
        guard identity.isOwnerExecutable else { throw HelperTrustError.executableNotRegularFile }
        let requirement = try HelperRequirement.make(
            identifier: identifier,
            teamIdentifier: policy.expectedTeamIdentifier
        )
        try signatures.verifyStaticCode(atPath: path, requirement: requirement)
        let info = try signatures.signingInfo(atPath: path)
        guard info.isProtectedIdentity,
              info.identifier == identifier,
              info.teamIdentifier == policy.expectedTeamIdentifier
        else {
            throw HelperTrustError.signatureRejected
        }
    }

    private func verifyProtectedAppBundle(_ path: String) throws {
        let identity = try files.identity(atPath: path)
        guard identity.isDirectory, !identity.isSymbolicLink else {
            throw HelperTrustError.signedAppMissing
        }
        guard identity.ownerIdentifier == 0 else {
            throw HelperTrustError.bundleNotOwnedByRoot
        }
        guard !identity.isGroupOrOtherWritable else { throw HelperTrustError.bundleWritable }
        guard try !files.hasWriteACL(atPath: path) else { throw HelperTrustError.bundleWritable }
        let requirement = try HelperRequirement.make(
            identifier: policy.appIdentifier,
            teamIdentifier: policy.expectedTeamIdentifier
        )
        try signatures.verifyStaticCode(atPath: path, requirement: requirement)
        let info = try signatures.signingInfo(atPath: path)
        guard info.isProtectedIdentity,
              info.identifier == policy.appIdentifier,
              info.teamIdentifier == policy.expectedTeamIdentifier
        else {
            throw HelperTrustError.signatureRejected
        }
    }

    // Check every directory between the executable and its trusted root. A
    // writable intermediate directory would let a user replace the file even
    // when the file itself is root-owned.
    private func verifyProtectedChain(from filePath: String, through root: String) throws {
        let prefix = root == "/" ? "/" : root + "/"
        var current = parent(of: filePath)
        while true {
            try verifyProtectedDirectory(current)
            if current == root { break }
            guard current.hasPrefix(prefix) else {
                throw HelperTrustError.unsafeParentDirectory
            }
            current = parent(of: current)
        }
    }

    private func verifyProtectedDirectory(_ path: String) throws {
        let identity = try files.identity(atPath: path)
        guard identity.isDirectory, !identity.isSymbolicLink else {
            throw HelperTrustError.unsafeParentDirectory
        }
        guard identity.ownerIdentifier == 0 else {
            throw HelperTrustError.unsafeParentDirectory
        }
        guard !identity.isGroupOrOtherWritable else {
            throw HelperTrustError.unsafeParentDirectory
        }
        guard try !files.hasWriteACL(atPath: path) else {
            throw HelperTrustError.unsafeParentDirectory
        }
    }

    private func verifyLaunchDaemonPlist(_ path: String, helperPath: String) throws {
        let canonical = try canonical(path: path)
        guard canonical == path, canonical.hasPrefix("/Library/LaunchDaemons/") else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        let identity = try files.identity(atPath: canonical)
        guard identity.isRegularFile, !identity.isSymbolicLink else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        guard identity.ownerIdentifier == 0, identity.groupIdentifier == 0 else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        guard !identity.isGroupOrOtherWritable else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        guard try !files.hasWriteACL(atPath: canonical) else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        let data: Data
        do {
            data = try reader.readFile(atPath: canonical, maximumBytes: 64 * 1024)
        } catch let error as HelperTrustError {
            throw error
        } catch {
            throw HelperTrustError.launchDaemonPlistMissing
        }
        try HelperLaunchDaemonPolicy.validate(
            plistData: data,
            helperPath: helperPath,
            serviceName: HelperRequirement.helperServiceName
        )
        try verifyProtectedChain(from: canonical, through: "/")
    }

    private func canonical(path: String) throws -> String {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        guard standardized == path else { throw HelperTrustError.pathIsNotCanonical }
        let resolved = try files.canonicalPath(path)
        guard resolved == path else { throw HelperTrustError.pathIsNotCanonical }
        return resolved
    }

    private func parent(of path: String) -> String {
        let parent = (path as NSString).deletingLastPathComponent
        return parent.isEmpty ? "/" : parent
    }
}

// The launch daemon file must name this helper and no other program. It must
// not keep the helper alive after a connection closes. A replaced plist is a
// root-only write, but this check also catches a packaging mistake.
public enum HelperLaunchDaemonPolicy {
    public static func validate(plistData: Data, helperPath: String, serviceName: String) throws {
        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
              let object = plist as? [String: Any]
        else {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        guard object["Label"] as? String == serviceName else {
            throw HelperTrustError.launchDaemonPlistMismatch
        }
        guard let services = object["MachServices"] as? [String: Any],
              let enabled = services[serviceName] as? Bool,
              enabled
        else {
            throw HelperTrustError.launchDaemonPlistMismatch
        }
        guard let arguments = object["ProgramArguments"] as? [String],
              arguments == [helperPath]
        else {
            throw HelperTrustError.launchDaemonPlistMismatch
        }
        if let runAtLoad = object["RunAtLoad"] as? Bool, runAtLoad {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        if let keepAlive = object["KeepAlive"] as? Bool, keepAlive {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        if let user = object["UserName"] as? String, user != "root" {
            throw HelperTrustError.launchDaemonPlistUnsafe
        }
        if let program = object["Program"] as? String, program != helperPath {
            throw HelperTrustError.launchDaemonPlistMismatch
        }
    }
}

// The helper also checks the engine that it will run as root. The engine lives
// under a root-owned directory and must carry the same team identity.
public struct RootOwnedExecutablePolicy: Sendable {
    public let path: String
    public let trustedRoot: String
    public let identifier: String
    public let teamIdentifier: String

    public init(path: String, trustedRoot: String, identifier: String, teamIdentifier: String) {
        self.path = path
        self.trustedRoot = trustedRoot
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
    }
}

public final class RootOwnedExecutableVerifier: Sendable {
    private let files: HelperFileInspecting
    private let signatures: HelperCodeSignatureChecking

    public init(
        files: HelperFileInspecting = SystemHelperFileSystem(),
        signatures: HelperCodeSignatureChecking = SecurityHelperCodeSignatureChecker()
    ) {
        self.files = files
        self.signatures = signatures
    }

    public func verify(_ policy: RootOwnedExecutablePolicy) throws -> String {
        guard HelperRequirement.isValidTeamIdentifier(policy.teamIdentifier),
              HelperRequirement.isValidIdentifier(policy.identifier)
        else {
            throw HelperTrustError.invalidSigningPolicy
        }
        let root = try files.canonicalPath(policy.trustedRoot)
        guard root == policy.trustedRoot,
              policy.path.hasPrefix(root + "/"),
              try files.canonicalPath(policy.path) == policy.path
        else {
            throw HelperTrustError.unsafeInstallRoot
        }
        var current = root
        while true {
            try verifyRootOwnedDirectory(current)
            if current == "/" { break }
            current = (current as NSString).deletingLastPathComponent
            if current.isEmpty { current = "/" }
        }
        var intermediate = (policy.path as NSString).deletingLastPathComponent
        while true {
            try verifyRootOwnedDirectory(intermediate)
            if intermediate == root { break }
            guard intermediate.hasPrefix(root + "/") else {
                throw HelperTrustError.unsafeParentDirectory
            }
            intermediate = (intermediate as NSString).deletingLastPathComponent
            if intermediate.isEmpty { intermediate = "/" }
        }
        let identity = try files.identity(atPath: policy.path)
        guard identity.isRegularFile, !identity.isSymbolicLink else {
            throw HelperTrustError.executableNotRegularFile
        }
        guard identity.ownerIdentifier == 0, identity.groupIdentifier == 0 else {
            throw HelperTrustError.executableNotOwnedByRoot
        }
        guard !identity.isGroupOrOtherWritable, identity.isOwnerExecutable else {
            throw HelperTrustError.executableWritable
        }
        guard try !files.hasWriteACL(atPath: policy.path) else {
            throw HelperTrustError.executableWritable
        }
        let requirement = try HelperRequirement.make(
            identifier: policy.identifier,
            teamIdentifier: policy.teamIdentifier
        )
        try signatures.verifyStaticCode(atPath: policy.path, requirement: requirement)
        let info = try signatures.signingInfo(atPath: policy.path)
        guard info.isProtectedIdentity,
              info.identifier == policy.identifier,
              info.teamIdentifier == policy.teamIdentifier
        else {
            throw HelperTrustError.signatureRejected
        }
        return policy.path
    }

    private func verifyRootOwnedDirectory(_ path: String) throws {
        let identity = try files.identity(atPath: path)
        // The group identifier need not be wheel. A root-owned directory with
        // no group or other write bit is still a boundary for a user process.
        // A stock /Library/Application Support is root:admin 0755.
        guard identity.isDirectory, !identity.isSymbolicLink,
              identity.ownerIdentifier == 0,
              !identity.isGroupOrOtherWritable
        else {
            throw HelperTrustError.unsafeParentDirectory
        }
        guard try !files.hasWriteACL(atPath: path) else {
            throw HelperTrustError.unsafeParentDirectory
        }
    }
}
