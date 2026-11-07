import Foundation
import Darwin

// The release executables are one thin arm64 Mach-O file each. A universal
// (fat) file is refused, not checked slice by slice. The Security framework
// checks one slice by default, so a fat file could carry a valid signed
// slice next to an unsigned or different one. A thin file has one slice, and
// the signature check covers all of it.
public enum MachOPolicy {
    public enum Verdict: Equatable, Sendable {
        case thinArm64Executable
        // The file does not start with a Mach-O or fat magic number.
        case notMachO
        // A Mach-O or fat file that is not one thin arm64 executable.
        case unsupported
    }

    static let cpuTypeARM64: UInt32 = 0x0100_000C
    static let fileTypeExecute: UInt32 = 2
    static let codeSignatureCommand: UInt32 = 0x1D
    static let headerSize = 32
    static let maximumCommands: UInt32 = 4096
    static let maximumCommandBytes: UInt32 = 1 << 20

    // Reads the file with O_NOFOLLOW. A symlink or a file that cannot be read
    // is `.notMachO`.
    public static func classify(atPath path: String) -> Verdict {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return .notMachO }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else { return .notMachO }
        let fileSize = UInt64(status.st_size)
        var header = [UInt8](repeating: 0, count: headerSize)
        guard readFully(descriptor, offset: 0, into: &header) else {
            // Too short for a header. A short file with a known magic is
            // unsupported; anything else is not a Mach-O file.
            return startsWithKnownMagic(path) ? .unsupported : .notMachO
        }
        switch Array(header[0..<4]) {
        case [0xCF, 0xFA, 0xED, 0xFE]:
            break
        case [0xCA, 0xFE, 0xBA, 0xBE], [0xCA, 0xFE, 0xBA, 0xBF],
             [0xBE, 0xBA, 0xFE, 0xCA], [0xBF, 0xBA, 0xFE, 0xCA],
             [0xCE, 0xFA, 0xED, 0xFE], [0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF]:
            // Fat, 32-bit, or big-endian. None is one thin arm64 executable.
            return .unsupported
        default:
            return .notMachO
        }
        let cpuType = le32(header, 4)
        let cpuSubtype = le32(header, 8)
        let fileType = le32(header, 12)
        let commandCount = le32(header, 16)
        let commandBytes = le32(header, 20)
        // The low 24 bits are the subtype. A capability bit in the top byte is
        // masked. Only ARM64_ALL (0) is accepted; arm64e is a different ABI.
        guard cpuType == cpuTypeARM64, cpuSubtype & 0x00FF_FFFF == 0, fileType == fileTypeExecute else {
            return .unsupported
        }
        guard commandCount >= 1, commandCount <= maximumCommands,
              commandBytes >= 8, commandBytes <= maximumCommandBytes,
              UInt64(headerSize) + UInt64(commandBytes) <= fileSize
        else {
            return .unsupported
        }
        var commands = [UInt8](repeating: 0, count: Int(commandBytes))
        guard readFully(descriptor, offset: off_t(headerSize), into: &commands) else { return .unsupported }
        var offset = 0
        var seen: UInt32 = 0
        var signatureInsideFile = false
        while offset < commands.count, seen < commandCount {
            guard offset + 8 <= commands.count else { return .unsupported }
            let command = le32(commands, offset)
            let size = Int(le32(commands, offset + 4))
            guard size >= 8, size % 8 == 0, offset + size <= commands.count else { return .unsupported }
            if command == codeSignatureCommand {
                guard size >= 16 else { return .unsupported }
                let dataOffset = UInt64(le32(commands, offset + 8))
                let dataSize = UInt64(le32(commands, offset + 12))
                guard dataSize > 0, dataOffset + dataSize <= fileSize else { return .unsupported }
                signatureInsideFile = true
            }
            offset += size
            seen += 1
        }
        // The load commands must end exactly where the header says.
        guard seen == commandCount, offset == commands.count, signatureInsideFile else { return .unsupported }
        return .thinArm64Executable
    }

    private static func startsWithKnownMagic(_ path: String) -> Bool {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        var magic = [UInt8](repeating: 0, count: 4)
        guard readFully(descriptor, offset: 0, into: &magic) else { return false }
        return [[0xCF, 0xFA, 0xED, 0xFE], [0xCA, 0xFE, 0xBA, 0xBE], [0xCA, 0xFE, 0xBA, 0xBF],
                [0xBE, 0xBA, 0xFE, 0xCA], [0xBF, 0xBA, 0xFE, 0xCA]].contains(magic)
    }

    private static func readFully(_ descriptor: Int32, offset: off_t, into buffer: inout [UInt8]) -> Bool {
        var done = 0
        while done < buffer.count {
            let count = buffer.withUnsafeMutableBytes {
                pread(descriptor, $0.baseAddress!.advanced(by: done), $0.count - done, offset + off_t(done))
            }
            if count < 0 {
                if errno == EINTR { continue }
                return false
            }
            if count == 0 { return false }
            done += count
        }
        return true
    }

    private static func le32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }
}
