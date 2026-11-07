import Foundation

@main
struct ProxyTokenTests {
    static func main() {
        // Equal content and equal length.
        precondition(constantTimeEquals([], []))
        precondition(constantTimeEquals([0], [0]))
        precondition(constantTimeEquals([1, 2, 3], [1, 2, 3]))
        precondition(constantTimeEquals(Array(repeating: 0x5a, count: 255),
                                        Array(repeating: 0x5a, count: 255)))

        // Unequal length. A matching prefix must not compare equal.
        precondition(!constantTimeEquals([], [0]))
        precondition(!constantTimeEquals([0], []))
        precondition(!constantTimeEquals([1, 2, 3], [1, 2]))
        precondition(!constantTimeEquals([1, 2], [1, 2, 3]))
        precondition(!constantTimeEquals(Array(repeating: 0, count: 255),
                                         Array(repeating: 0, count: 256)))
        precondition(!constantTimeEquals(Array(repeating: 0, count: 256),
                                         Array(repeating: 0, count: 255)))
        // A length difference of 256 has the same low eight bits. The result
        // must still differ.
        precondition(!constantTimeEquals(Array(repeating: 0, count: 255),
                                         Array(repeating: 0, count: 511)))

        // Unequal content at the first, middle, and last byte.
        precondition(!constantTimeEquals([2, 2, 3], [1, 2, 3]))
        precondition(!constantTimeEquals([1, 9, 3], [1, 2, 3]))
        precondition(!constantTimeEquals([1, 2, 4], [1, 2, 3]))

        // The real shape: an ASCII token with one changed last byte.
        let token = Array("0123456789abcdef".utf8)
        var wrong = token
        wrong[wrong.count - 1] ^= 0xff
        precondition(constantTimeEquals(token, token))
        precondition(!constantTimeEquals(token, wrong))
        print("Proxy token tests passed")
    }
}
