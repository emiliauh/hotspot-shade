import Foundation
import Darwin

// Small, fixed syscall helpers with one rule each. No helper builds a shell
// command or interprets a path from an input.
enum SystemSupport {
    // True when an extended ACL is present or its state cannot be read. The
    // callers refuse either case. Darwin reports no extended ACL as ENOENT;
    // an error other than ENOENT must never be treated as a clean object.
    static func hasExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno != ENOENT
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    static func hasExtendedACL(path: String) -> Bool {
        errno = 0
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            guard errno == ENOENT else { return true }
            // ENOENT also means the path itself disappeared. Refuse when a
            // subsequent path check cannot establish that an object exists.
            // This is a point-in-time check, not an atomic path guarantee.
            var metadata = stat()
            guard lstat(path, &metadata) == 0 else { return true }
            // acl_get_file follows links, while lstat does not. Do not treat a
            // link or dangling link as an ACL-free object.
            return (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFLNK)
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    // Write every byte. A short write is retried. A signal interruption is
    // retried. Any other failure returns false.
    static func writeAll(_ descriptor: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return data.isEmpty }
            var sent = 0
            while sent < buffer.count {
                let written = write(descriptor, base.advanced(by: sent), buffer.count - sent)
                if written > 0 {
                    sent += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
    }

    static func writeAll(_ descriptor: Int32, bytes: [UInt8]) -> Bool {
        writeAll(descriptor, data: Data(bytes))
    }

    // Read at most `maximumBytes` and refuse a file that is larger. The
    // descriptor position is advanced. The caller checks the file type and
    // size through the same descriptor before calling.
    static func readAll(_ descriptor: Int32, maximumBytes: Int) -> Data? {
        guard maximumBytes > 0 else { return nil }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if count == 0 { return result }
            guard result.count + count <= maximumBytes else { return nil }
            result.append(contentsOf: buffer[0..<count])
        }
    }

    static func isLowercaseHex(_ text: String, count: Int) -> Bool {
        guard text.utf8.count == count else { return false }
        for byte in text.utf8 {
            let allowed = (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)
            guard allowed else { return false }
        }
        return true
    }

    static func randomHex(byteCount: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        var text = ""
        text.reserveCapacity(byteCount * 2)
        for _ in 0..<byteCount {
            text += String(format: "%02x", UInt8.random(in: 0...255, using: &generator))
        }
        return text
    }

    // A temporary name suffix is a transaction identifier plus one index. It
    // is never read from a file.
    static func isSafeSuffix(_ text: String) -> Bool {
        guard !text.isEmpty, text.utf8.count <= 80 else { return false }
        for byte in text.utf8 {
            let allowed = (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x61 && byte <= 0x66)
                || byte == 0x2D
            guard allowed else { return false }
        }
        return true
    }
}
