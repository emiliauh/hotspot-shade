import Foundation
import Security

final class FakeRecoveryIntentStore: RecoveryIntentStore {
    var data: Data?
    var readError: SecureTokenError?
    var writeError: SecureTokenError?
    var writeErrorAfterStore: SecureTokenError?
    var clearError: SecureTokenError?
    var clearErrorAfterClear: SecureTokenError?
    /// Runs before a write applies. A test uses it to model another writer.
    var onWrite: (() -> Void)?
    private(set) var readCount = 0
    private(set) var writeCount = 0
    private(set) var clearCount = 0

    func read() throws -> Data? {
        readCount += 1
        if let readError { throw readError }
        return data
    }

    func write(_ data: Data) throws {
        writeCount += 1
        onWrite?()
        if let writeError { throw writeError }
        self.data = data
        if let writeErrorAfterStore { throw writeErrorAfterStore }
    }

    func clear() throws {
        clearCount += 1
        if let clearError { throw clearError }
        data = nil
        if let clearErrorAfterClear { throw clearErrorAfterClear }
    }
}

/// Models the Keychain's add-only insert and update/delete by item attributes.
final class StatefulKeychainAPI: KeychainAPI {
    private var items: [String: Data] = [:]
    var beforeAdd: ((KeychainItemID) -> Void)?
    var beforeUpdate: ((KeychainItemID) -> Void)?
    var beforeDelete: ((KeychainItemID) -> Void)?
    private func key(_ item: KeychainItemID) -> String {
        "\(item.service)\u{0}\(item.account)\u{0}\(item.synchronizable)"
    }
    func set(_ item: KeychainItemID, _ data: Data?) { items[key(item)] = data }
    func copy(_ item: KeychainItemID) -> (status: Int32, data: Data?) {
        guard let data = items[key(item)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, data)
    }
    func add(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        beforeAdd?(item)
        guard items[key(item)] == nil else { return errSecDuplicateItem }
        items[key(item)] = data
        return errSecSuccess
    }
    func update(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        beforeUpdate?(item)
        guard items[key(item)] != nil else { return errSecItemNotFound }
        items[key(item)] = data
        return errSecSuccess
    }
    func delete(_ item: KeychainItemID) -> Int32 {
        beforeDelete?(item)
        guard items.removeValue(forKey: key(item)) != nil else { return errSecItemNotFound }
        return errSecSuccess
    }
}

// Hermetic fakes for the token stores. They never open the real keychain or
// UserDefaults. SecureTokenStoreTests and TokenLifecycleTests share them.

final class FakeTokenStorage: TokenStorage {
    enum ReadStep {
        case value(String?)
        case failure(SecureTokenError)
        case failureAndStore(SecureTokenError, String?)
        /// Another writer replaced the item before this read.
        case valueAndStore(String?)
    }

    enum WriteStep {
        case store
        case failure(SecureTokenError)
        case failureButStore(SecureTokenError)
    }

    enum DeleteStep {
        case remove
        case failure(SecureTokenError)
        case failureButRemove(SecureTokenError)
    }

    var stored: String?
    var readSteps: [ReadStep] = []
    var writeSteps: [WriteStep] = []
    var deleteSteps: [DeleteStep] = []
    /// Runs inside a write, before the write result is applied. A test uses it
    /// to model another writer that changes UserDefaults or the Keychain.
    var onWrite: (() -> Void)?

    private(set) var readCount = 0
    private(set) var writeCount = 0
    private(set) var deleteCount = 0
    private(set) var written: [String] = []

    init(stored: String? = nil) {
        self.stored = stored
    }

    func readToken() throws -> String? {
        readCount += 1
        guard !readSteps.isEmpty else { return stored }
        switch readSteps.removeFirst() {
        case .value(let value):
            return value
        case .failure(let error):
            throw error
        case .failureAndStore(let error, let value):
            stored = value
            throw error
        case .valueAndStore(let value):
            stored = value
            return value
        }
    }

    func addToken(_ token: String) throws {
        try applyWrite(token, addOnly: true)
    }

    func writeToken(_ token: String) throws {
        try applyWrite(token, addOnly: false)
    }

    private func applyWrite(_ token: String, addOnly: Bool) throws {
        writeCount += 1
        written.append(token)
        onWrite?()
        if addOnly && stored != nil { throw SecureTokenError.tokenAlreadyPresent }
        if !addOnly && stored == nil { throw SecureTokenError.keychainWriteFailed(errSecItemNotFound) }
        guard !writeSteps.isEmpty else {
            stored = token
            return
        }
        switch writeSteps.removeFirst() {
        case .store:
            stored = token
        case .failure(let error):
            throw error
        case .failureButStore(let error):
            stored = token
            throw error
        }
    }

    func deleteToken() throws {
        deleteCount += 1
        guard !deleteSteps.isEmpty else {
            stored = nil
            return
        }
        switch deleteSteps.removeFirst() {
        case .remove:
            stored = nil
        case .failure(let error):
            throw error
        case .failureButRemove(let error):
            stored = nil
            throw error
        }
    }
}

final class FakeLegacyStore: LegacyTokenStore {
    var value: String?
    var removeResult = true
    var onLoad: ((Int) -> Void)?
    /// Runs at the start of a removal. A test uses it to model a different
    /// writer that changes the old copy between the store's check and delete.
    var onRemove: (() -> Void)?

    private(set) var loadCount = 0
    private(set) var removeCount = 0

    init(value: String? = nil) {
        self.value = value
    }

    func loadToken() -> String? {
        loadCount += 1
        onLoad?(loadCount)
        return value
    }

    @discardableResult
    func removeToken() -> Bool {
        removeCount += 1
        onRemove?()
        if removeResult { value = nil }
        return removeResult
    }
}

final class TokenFeed {
    private var values: [String?]
    private(set) var calls = 0

    init(_ values: [String?]) {
        self.values = values
    }

    func next() -> String? {
        calls += 1
        guard !values.isEmpty else { return nil }
        return values.removeFirst()
    }
}

final class FakeKeychainAPI: KeychainAPI {
    var copyResults: [(status: Int32, data: Data?)] = []
    var addResults: [Int32] = []
    var updateResults: [Int32] = []
    var deleteResults: [Int32] = []

    var defaultCopy: (status: Int32, data: Data?) = (errSecItemNotFound, nil)
    var defaultAdd: Int32 = errSecSuccess
    var defaultUpdate: Int32 = errSecSuccess
    var defaultDelete: Int32 = errSecSuccess

    private(set) var copyCount = 0
    private(set) var addCount = 0
    private(set) var updateCount = 0
    private(set) var deleteCount = 0
    private(set) var lastItem: KeychainItemID?
    private(set) var lastAccessible: String?
    private(set) var addItems: [KeychainItemID] = []
    private(set) var updateItems: [KeychainItemID] = []

    func copy(_ item: KeychainItemID) -> (status: Int32, data: Data?) {
        copyCount += 1
        lastItem = item
        guard !copyResults.isEmpty else { return defaultCopy }
        return copyResults.removeFirst()
    }

    func add(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        addCount += 1
        lastItem = item
        addItems.append(item)
        lastAccessible = accessible
        guard !addResults.isEmpty else { return defaultAdd }
        return addResults.removeFirst()
    }

    func update(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        updateCount += 1
        lastItem = item
        updateItems.append(item)
        lastAccessible = accessible
        guard !updateResults.isEmpty else { return defaultUpdate }
        return updateResults.removeFirst()
    }

    func delete(_ item: KeychainItemID) -> Int32 {
        deleteCount += 1
        lastItem = item
        guard !deleteResults.isEmpty else { return defaultDelete }
        return deleteResults.removeFirst()
    }
}
