import Foundation
import Darwin
import CryptoKit

public struct IngestedFile: Equatable, Sendable {
    public let sha256: String
    public let size: Int
}

// Copy one supplied file into a private staging directory. Every later check
// reads the staged copy, never the supplied path, so a supplied file that
// changes after the copy cannot pass a check and then differ in the package.
public enum ArtifactIngest {
    public static let maximumExecutableBytes = 256 * 1024 * 1024
    public static let maximumPlistBytes = 64 * 1024

    public static func copy(
        source: String,
        destination: String,
        artifact: InstallerArtifact,
        maximumBytes: Int
    ) throws -> IngestedFile {
        // O_NOFOLLOW refuses a final symlink. The descriptor is checked with
        // fstat, so the type test applies to the object that is read.
        // A supplied FIFO must not block before fstat can reject it. Nonblocking
        // mode has no effect on reads from the regular files accepted below.
        let input = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard input >= 0 else { throw InstallerError.inputUnreadable(artifact) }
        defer { close(input) }
        var status = stat()
        guard fstat(input, &status) == 0 else { throw InstallerError.inputUnreadable(artifact) }
        guard status.st_mode & S_IFMT == S_IFREG else {
            throw InstallerError.inputNotRegularFile(artifact)
        }
        guard status.st_size > 0, status.st_size <= off_t(maximumBytes) else {
            throw InstallerError.inputTooLarge(artifact)
        }
        let output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw InstallerError.stagingFailed("cannot create a staged file") }
        var succeeded = false
        defer {
            close(output)
            if !succeeded { unlink(destination) }
        }
        var hasher = SHA256()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(input, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw InstallerError.inputUnreadable(artifact)
            }
            if count == 0 { break }
            total += count
            // A file that grows while it is read is refused.
            guard total <= maximumBytes else { throw InstallerError.inputTooLarge(artifact) }
            hasher.update(data: buffer[0..<count])
            var written = 0
            while written < count {
                let result = buffer.withUnsafeBytes {
                    write(output, $0.baseAddress!.advanced(by: written), count - written)
                }
                if result < 0 {
                    if errno == EINTR { continue }
                    throw InstallerError.stagingFailed("cannot write a staged file")
                }
                written += result
            }
        }
        guard total == Int(status.st_size) else { throw InstallerError.inputUnreadable(artifact) }
        guard fsync(output) == 0 else { throw InstallerError.stagingFailed("cannot sync a staged file") }
        succeeded = true
        return IngestedFile(sha256: hex(hasher.finalize()), size: total)
    }

    public static func sha256(ofFileAt path: String, artifact: InstallerArtifact) throws -> IngestedFile {
        let input = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard input >= 0 else { throw InstallerError.inputUnreadable(artifact) }
        defer { close(input) }
        var status = stat()
        guard fstat(input, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw InstallerError.inputNotRegularFile(artifact)
        }
        var hasher = SHA256()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(input, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw InstallerError.inputUnreadable(artifact)
            }
            if count == 0 { break }
            total += count
            hasher.update(data: buffer[0..<count])
        }
        return IngestedFile(sha256: hex(hasher.finalize()), size: total)
    }

    static func hex(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

extension ArtifactIngest {
    // For a file that this tool wrote itself, such as a script.
    static func sha256(ofStagedFileAt path: String) throws -> IngestedFile {
        do { return try sha256(ofFileAt: path, artifact: .helper) } catch {
            throw InstallerError.stagingFailed("cannot read a staged file")
        }
    }
}
