import Foundation
import Darwin

// Hermetic helpers for the protected helper tests. These run as the test user
// in a temporary directory. They never touch a system path, a route, or a TUN
// device.
enum ProtectedHelperTestSupport {
    // Add one harmless extended ACL entry. The tests only need a non-nil ACL;
    // the permission itself is not what the helper rejects.
    static func addExtendedACL(to path: String) -> Bool {
        var acl = acl_init(1)
        guard acl != nil else { return false }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        guard acl_create_entry(&acl, &entry) == 0, let entry else { return false }
        guard acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0 else { return false }
        var permissions: acl_permset_t?
        guard acl_get_permset(entry, &permissions) == 0, let permissions else {
            return false
        }
        guard acl_add_perm(permissions, ACL_READ_DATA) == 0 else { return false }
        guard acl_set_permset(entry, permissions) == 0 else { return false }
        return acl_set_file(path, ACL_TYPE_EXTENDED, acl) == 0
    }
}
