import Foundation
import HotspotShadeKit

// The two package scripts. They hold no value that comes from an input. Every
// path and name below is a fixed constant from `InstallerLayout`. The scripts
// use absolute tool paths and never name a shell variable for a program. The
// generated preinstall script refuses before any check or change, because this
// foundation package has no approved single-lock installation exclusion. The
// sandbox-only coordinator in this package does not change the gate. The
// postinstall text is future code that Installer cannot reach while the gate is
// fixed. They are generated text. This package never runs them as root, and
// their behavior on a real host is unverified. The tests run the pure functions
// in a temporary directory and the refusal with /bin/sh.
public enum InstallerScripts {
    public static let preinstallName = "preinstall"
    public static let postinstallName = "postinstall"

    // The package is a build-only foundation. It has no exclusion that is held
    // for a whole installation and shared by the helper, the direct command
    // line start, and every other root start path. The generated preinstall
    // script therefore refuses before it reads any process, marker, or job.
    // This value is not configurable from an argument, an environment variable,
    // or a file.
    public static let installationApproved = false

    // Pure mode arithmetic. $1 is the octal text that `stat -f %Lp` prints. The
    // text has no fixed length: a mode such as 70 has two digits and 1755 has
    // four, so the script never slices the text by position.
    public static let modeFunctions = #"""
    # Set MODE_VALUE to the integer value of one octal mode text.
    parse_mode() {
        case "$1" in
            ''|*[!0-7]*) refuse "the mode text is not octal: $1" ;;
        esac
        if [ "${#1}" -gt 4 ]; then
            refuse "the mode text is too long: $1"
        fi
        MODE_VALUE=$((0$1))
    }

    # $1 is a path for the message and $2 is the octal mode text. A group or
    # other write bit and a set-id bit are refused. The sticky bit is allowed,
    # because /Library/PrivilegedHelperTools carries it.
    refuse_unsafe_mode() {
        parse_mode "$2"
        if [ $((MODE_VALUE & 0022)) -ne 0 ]; then
            refuse "$1 is writable by a group or others"
        fi
        if [ $((MODE_VALUE & 06000)) -ne 0 ]; then
            refuse "$1 has a set-id bit"
        fi
    }

    # An access control list can grant a write that the mode bits do not show,
    # and this script does not interpret one. Any entry is a refusal. The
    # status of `ls` is checked on its own, so a failed listing refuses instead
    # of looking like an empty list. A file name that contains a newline also
    # adds a line; refusing it is the safe direction.
    refuse_if_acl() {
        if ! listing="$(/bin/ls -lde "$1" 2>/dev/null)"; then
            refuse "$1 could not be read for an access control list"
        fi
        case "$listing" in
            *'\#n'*) refuse "$1 has an access control list" ;;
        esac
    }
    """#

    // The exact allowlist for a stored start right. `security authorizationdb
    // read` writes the stored definition to a file. Every top-level key must be
    // a known key with a known type and value. A merged or extended definition
    // that keeps an extra key, such as a rule or a mechanism list, is refused.
    // The helper's own validator stays the full check at startup. This block
    // must never accept a definition that the helper validator refuses.
    //
    // The key check is structured. It converts the read-back to XML1 and asks
    // xmllint for an XPath verdict over the parsed property list. It does not
    // read `plutil -p` text, which an empty key or a key with a line break can
    // make ambiguous. The query refuses an empty key, a key with a line break,
    // an unknown key, a duplicate key, and a second root element. xmllint is
    // invoked with --nonet so a plist doctype cannot fetch anything.
    public static let rightFunctions = #"""
    # Set RIGHT_PRESENT to 1 when one direct child key has this exact name and
    # to 0 when the parsed property list has no such key. The XML reader and
    # plutil must agree. A reader error, a tool error, or a disagreement is a
    # refusal, never absence.
    right_has_key() {
        if ! presence="$(/usr/bin/xmllint --nonet --xpath "boolean(/plist/dict/key[. = \"$1\"])" "$right_file" 2>/dev/null)"; then
            refuse "the stored start right could not be inspected for $1"
        fi
        case "$presence" in
            true) RIGHT_PRESENT=1 ;;
            false) RIGHT_PRESENT=0 ;;
            *) refuse "the stored start right could not be inspected for $1" ;;
        esac
    }

    # Set RIGHT_TYPE to the exact type of one top-level key, or to empty when
    # the key is absent. plutil -type fails for an absent key, so its failure is
    # absence only when the XML reader also reports the key absent. Any other
    # failure, and any disagreement between the two readers, refuses.
    right_type() {
        right_has_key "$1"
        if plutil_type="$(/usr/bin/plutil -type "$1" "$right_file" 2>/dev/null)"; then
            if [ "$RIGHT_PRESENT" -eq 0 ]; then
                refuse "the stored start right could not be inspected for $1"
            fi
            if [ -z "$plutil_type" ]; then
                refuse "the stored start right could not be read for $1"
            fi
            RIGHT_TYPE=$plutil_type
        else
            if [ "$RIGHT_PRESENT" -eq 1 ] || [ -n "$plutil_type" ]; then
                refuse "the stored start right could not be read for $1"
            fi
            RIGHT_TYPE=""
        fi
    }

    # Set RAW_VALUE to the exact text of one present top-level key. A command
    # substitution drops trailing newlines, so a sentinel byte is appended and
    # removed again. plutil adds one newline of its own, which is removed too.
    # The status check comes before the sentinel can turn a failed extraction
    # into an empty value. Without the newline step, a value that ends in a
    # newline would pass as one without.
    right_load() {
        if ! RAW_VALUE="$( { /usr/bin/plutil -extract "$1" raw -o - "$right_file" 2>/dev/null && printf x; } )"; then
            refuse "the stored start right could not be read for $1"
        fi
        case "$RAW_VALUE" in
            *x) RAW_VALUE="${RAW_VALUE%x}" ;;
            *) refuse "the stored start right could not be read for $1" ;;
        esac
        case "$RAW_VALUE" in
            *'\#n') RAW_VALUE="${RAW_VALUE%'\#n'}" ;;
            *) refuse "the stored start right could not be read for $1" ;;
        esac
    }

    # $1 key, $2 type, $3 exact value.
    right_expect() {
        right_type "$1"
        if [ "$RIGHT_TYPE" != "$2" ]; then
            refuse "the stored start right differs for $1"
        fi
        right_load "$1"
        if [ "$RAW_VALUE" != "$3" ]; then
            refuse "the stored start right differs for $1"
        fi
    }

    # A present key must be one of two types. A missing key is allowed.
    right_optional_type() {
        right_type "$1"
        if [ -n "$RIGHT_TYPE" ] && [ "$RIGHT_TYPE" != "$2" ] && [ "$RIGHT_TYPE" != "$3" ]; then
            refuse "the stored start right has the wrong type for $1"
        fi
    }

    # $1 key, $2 lowest, $3 highest. A present key must be an integer in range.
    right_integer_in() {
        right_type "$1"
        if [ -z "$RIGHT_TYPE" ]; then
            return 0
        fi
        if [ "$RIGHT_TYPE" != integer ]; then
            refuse "the stored start right has the wrong type for $1"
        fi
        right_load "$1"
        value="$RAW_VALUE"
        case "$value" in
            ''|*[!0-9]*) refuse "the stored start right has a bad value for $1" ;;
        esac
        if [ "${#value}" -gt 9 ] || [ "$value" -lt "$2" ] || [ "$value" -gt "$3" ]; then
            refuse "the stored start right has a bad value for $1"
        fi
    }

    # $1 key, $2 longest value in bytes, $3 characters to allow besides the
    # printable range, as a tr octal list ('' for none).
    right_text() {
        right_type "$1"
        if [ -z "$RIGHT_TYPE" ]; then
            return 0
        fi
        if [ "$RIGHT_TYPE" != string ]; then
            refuse "the stored start right has the wrong type for $1"
        fi
        right_load "$1"
        value="$RAW_VALUE"
        if [ -z "$value" ] || [ "${#value}" -gt "$2" ]; then
            refuse "the stored start right has a bad value for $1"
        fi
        # Whatever tr leaves is a byte that is not allowed. The sentinel keeps a
        # leftover newline from being dropped by the substitution. A failed
        # filter is a refusal, not an empty result that passes.
        if ! rest="$(printf '%s' "$value" | { /usr/bin/tr -d "\040-\176$3"; status=$?; printf x; exit "$status"; })"; then
            refuse "the stored start right could not be checked for $1"
        fi
        if [ "$rest" != x ]; then
            refuse "the stored start right has a bad value for $1"
        fi
    }

    right_timestamp() {
        right_optional_type "$1" integer float
        if [ -z "$RIGHT_TYPE" ]; then
            return 0
        fi
        right_load "$1"
        value="$RAW_VALUE"
        case "$value" in
            ''|-*|*[!0-9.eE+-]*) refuse "the stored start right has a bad value for $1" ;;
        esac
    }

    # A structured check of every top-level key in the stored right. The query
    # requires exactly one root dictionary, no duplicate direct key, and every
    # direct child key to be one known name. An empty key and a key with a line
    # break are simply not equal to any allowed name. The allowlist query runs
    # over the XML1 form, so a binary plist and an XML plist take the same path.
    right_check_keys() {
        if [ ! -x /usr/bin/xmllint ]; then
            refuse "the property list key check is unavailable"
        fi
        # The XML1 conversion rewrites a dictionary and keeps one value for a
        # duplicate key. Check the original text for a duplicate when the XML
        # reader can parse it. A binary plist cannot be read here; the
        # conversion below then gives the same last value that the helper's
        # parser sees.
        if duplicate="$(/usr/bin/xmllint --nonet --xpath 'count(/plist/dict/key[. = preceding-sibling::key])' "$right_file" 2>/dev/null)"; then
            if [ "$duplicate" != 0 ]; then
                refuse "the stored start right holds an unknown, empty, duplicate, or malformed key"
            fi
        fi
        /usr/bin/plutil -convert xml1 "$right_file" >/dev/null 2>&1 \
            || refuse "the stored start right is not a property list"
        if ! verdict="$(/usr/bin/xmllint --nonet --xpath 'count(/plist) = 1
            and count(/plist/dict) = 1
            and count(/plist/dict/key[. = preceding-sibling::key]) = 0
            and count(/plist/dict/key[not(
                . = "class" or . = "group" or . = "authenticate-user" or
                . = "shared" or . = "allow-root" or . = "timeout" or
                . = "comment" or . = "created" or . = "modified" or
                . = "version" or . = "identifier" or . = "requirement" or
                . = "session-owner" or . = "tries")]) = 0' \
            "$right_file" 2>/dev/null)"; then
            refuse "the property list key check failed"
        fi
        if [ "$verdict" != true ]; then
            refuse "the stored start right holds an unknown, empty, duplicate, or malformed key"
        fi
    }

    # $1 is a plist file that holds a stored right.
    check_right_file() {
        right_file="$1"
        /usr/bin/plutil -lint "$right_file" >/dev/null 2>&1 || refuse "the stored start right is not a property list"
        right_check_keys
        right_expect class string user
        right_expect group string admin
        right_expect authenticate-user bool true
        right_expect shared bool false
        right_expect allow-root bool false
        # The timeout must be present and inside the same bounded positive
        # window as the helper validator. Zero stores no credential for the
        # helper check that follows the administrator prompt.
        right_type timeout
        if [ -z "$RIGHT_TYPE" ]; then
            refuse "the stored start right has no timeout"
        fi
        right_integer_in timeout \#(HelperStartAuthorizationPolicy.startRightTimeoutBounds.lowerBound) \#(HelperStartAuthorizationPolicy.startRightTimeoutBounds.upperBound)
        right_type comment
        if [ -n "$RIGHT_TYPE" ] && [ "$RIGHT_TYPE" != string ]; then
            refuse "the stored start right has the wrong type for comment"
        fi
        right_timestamp created
        right_timestamp modified
        right_integer_in version 0 1000000
        right_integer_in tries 1 10000
        right_text identifier 1024 "\011"
        right_text requirement 4096 "\011\012\015"
        right_type session-owner
        if [ -n "$RIGHT_TYPE" ]; then
            right_expect session-owner bool false
        fi
    }
    """#

    public static var preinstall: String {
        header + """


        # This package is a build-only foundation. It has no exclusion
        # mechanism that is held for the whole installation and shared by the
        # helper, the direct command line start, and every other root start
        # path. The process, marker, and launchd checks in an earlier draft
        # were observations: a start could happen after the last one. It also
        # cannot hold a lock across the payload replacement, because Installer
        # runs preinstall and postinstall as separate processes.
        #
        # Refuse before the first check or change. No argument, environment
        # variable, or file can turn this gate off. See macos/Installer/README.md
        # for the lock and coordinator design that a later approved package
        # needs.
        refuse "this package is a build-only foundation and is not approved for installation"

        """
    }

    public static var postinstall: String {
        header + """


        \(modeFunctions)

        \(rightFunctions)

        STATE_DIR="\(InstallerLayout.stateDirectory)"
        HOME_DIR="\(InstallerLayout.engineHome)"
        DAEMON_PLIST="\(InstallerLayout.launchDaemonDestination)"
        HELPER="\(InstallerLayout.helperDestination)"
        ENGINE="\(InstallerLayout.engineDestination)"
        STAGED_HELPER="\(InstallerLayout.stagedHelperPath)"
        STAGED_DAEMON_PLIST="\(InstallerLayout.stagedLaunchDaemonPath)"
        RIGHT="\(InstallerLayout.startRightName)"
        RIGHT_PLIST="\(InstallerLayout.startRightDestination)"

        # One file: a regular file, root:wheel, one link, no access control
        # list, and an exact mode. $1 is the path and $2 is the octal mode.
        check_file() {
            if [ -L "$1" ] || [ ! -f "$1" ]; then
                refuse "$1 is missing or is not a regular file"
            fi
            if [ "$(/usr/bin/stat -f '%u:%g:%l' "$1")" != "0:0:1" ]; then
                refuse "$1 has the wrong owner, group, or link count"
            fi
            parse_mode "$(/usr/bin/stat -f '%Lp' "$1")"
            if [ "$MODE_VALUE" -ne $((0$2)) ]; then
                refuse "$1 has the wrong mode"
            fi
            refuse_if_acl "$1"
        }

        # One directory that other code relies on: root-owned, not a symlink, no
        # group or other write bit, no set-id bit, and no access control list.
        # The script never changes an existing directory that fails this.
        check_directory() {
            if [ -L "$1" ] || [ ! -d "$1" ]; then
                refuse "$1 is missing or is not a directory"
            fi
            if [ "$(/usr/bin/stat -f '%u' "$1")" != "0" ]; then
                refuse "$1 is not owned by root"
            fi
            refuse_unsafe_mode "$1" "$(/usr/bin/stat -f '%Lp' "$1")"
            refuse_if_acl "$1"
        }

        # A root-only directory. A missing one is created. An existing one must
        # already be root-owned; its owner is never taken from a user. It is
        # then set to root:wheel 0700 and read back.
        make_private_directory() {
            if [ -L "$1" ]; then
                refuse "$1 is a symlink"
            fi
            if [ -e "$1" ]; then
                if [ ! -d "$1" ]; then
                    refuse "$1 is not a directory"
                fi
                if [ "$(/usr/bin/stat -f '%u' "$1")" != "0" ]; then
                    refuse "$1 is not owned by root"
                fi
                /usr/sbin/chown root:wheel "$1"
                /bin/chmod 0700 "$1"
            else
                /usr/bin/install -d -o root -g wheel -m 0700 "$1"
            fi
            if [ -L "$1" ] || [ ! -d "$1" ]; then
                refuse "$1 is not a directory after it was prepared"
            fi
            if [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$1")" != "0:0:700" ]; then
                refuse "$1 is not root:wheel 0700 after it was prepared"
            fi
            refuse_if_acl "$1"
        }

        # The package payload must be intact and root-owned, and every directory
        # above it must be one that only root can change.
        for dir in "/Library" "/Library/Application Support" "\(InstallerLayout.installLocation)" \
            "\(InstallerLayout.engineRoot)" "\(InstallerLayout.supportRoot)"; do
            check_directory "$dir"
        done
        check_file "$ENGINE" 755
        check_file "$STAGED_HELPER" 644
        check_file "$STAGED_DAEMON_PLIST" 644
        check_file "$RIGHT_PLIST" 644

        # Put the helper and its launch daemon file in the protected paths.
        # install -d creates only a missing directory. An existing one is
        # checked and never changed.
        for dir in "\(InstallerLayout.helperInstallRoot)" "\(InstallerLayout.launchDaemonRoot)"; do
            if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
                /usr/bin/install -d -o root -g wheel -m 0755 "$dir"
            fi
            check_directory "$dir"
        done
        /usr/bin/install -S -o root -g wheel -m 0755 "$STAGED_HELPER" "$HELPER"
        /usr/bin/install -S -o root -g wheel -m 0644 "$STAGED_DAEMON_PLIST" "$DAEMON_PLIST"
        /usr/bin/cmp -s "$STAGED_HELPER" "$HELPER" || refuse "the installed helper differs from the package"
        /usr/bin/cmp -s "$STAGED_DAEMON_PLIST" "$DAEMON_PLIST" || refuse "the installed launch daemon file differs"
        check_file "$HELPER" 755
        check_file "$DAEMON_PLIST" 644

        # The engine home and the state directory are root-only. The helper also
        # creates them on demand. A parent must be a root-owned directory. The
        # cleanup state files inside the state directory are never touched.
        for dir in "$HOME_DIR" "$STATE_DIR"; do
            parent="${dir%/*}"
            if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
                /bin/mkdir -p "$parent"
            fi
            check_directory "$parent"
            make_private_directory "$dir"
        done

        # Install the start right unconditionally, then read it back. The
        # read-back must match the exact allowlist in check_right_file, so a
        # write that merged into an older definition fails here. A failure
        # leaves the right in place and the helper unregistered. The script
        # never removes a right. The helper validates the stored definition again
        # at startup and before every start.
        /usr/bin/security authorizationdb write "$RIGHT" < "$RIGHT_PLIST" >/dev/null \
            || refuse "the start right could not be written"
        readback="$(/usr/bin/mktemp -t hotspotshade-right)" || refuse "no temporary file"
        trap '/bin/rm -f "$readback"' EXIT
        /usr/bin/security authorizationdb read "$RIGHT" > "$readback" 2>/dev/null \
            || refuse "the start right could not be read back"
        check_right_file "$readback"

        # Register the helper with launchd. The job has RunAtLoad false, so
        # this starts nothing. launchd starts the helper on the first XPC lookup.
        /bin/launchctl bootstrap system "$DAEMON_PLIST" || refuse "the helper could not be registered"
        exit 0

        """
    }

    private static var header: String {
        """
        #!/bin/sh
        # Generated by hotspotshade-installer-build. Would run as root during
        # install. This package is not approved for installation: preinstall
        # refuses before any check or change. Fixed paths only. It never
        # touches a route, an interface, a process signal, or the cleanup state
        # files. Unverified on a real host.
        set -eu
        umask 022
        PATH=/usr/bin:/bin:/usr/sbin:/sbin
        LC_ALL=C
        export PATH LC_ALL

        refuse() {
            /bin/echo "HotspotShade install refused: $1" >&2
            exit 1
        }
        """
    }
}
