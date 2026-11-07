# Start-right fixtures

These fixtures are sanitized copies of the plist shape that a read-only
`security authorizationdb read` returns on macOS 27.2 for a stored right. The
built-in `system.privilege.admin` and `system.preferences` reads supplied the
key set and value types. Timestamps, comments, identifiers, and requirement
strings are fixed public values, not values from a real user or application.

- `start-right-authd-read.plist` is the shape the installer template gains
  after authd adds `created`, `modified`, `session-owner`, `tries`, and
  `version`. It must be accepted.
- `start-right-authd-identity.plist` adds the `identifier` and `requirement`
  metadata that a third-party application can leave on a right. It must be
  accepted because those keys do not decide who may obtain the right.
- `start-right-malicious-rule.plist` adds `rule`, `k-of-n`, and `mechanisms`.
  It also carries `identifier` and `requirement`, so the test proves that the
  tolerated metadata cannot mask an access-granting key.
- `start-right-malicious-entitled.plist` adds `entitled-group` and
  `entitlement`.

The malicious fixtures must be refused. These are hermetic files. No custom
right was installed, and no live authd read of the HotspotShade right was
performed.

Every fixture uses the reviewed 10 second `timeout` window. That keeps the
malicious fixtures refused for their access-granting keys, not for an
out-of-window timeout.
