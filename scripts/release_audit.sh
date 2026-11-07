#!/bin/sh
# Hermetic release audit for HotspotShade.
#
# The audit reads the tree and, when asked, the files in an artifact directory.
# It does not build, download, change a route, create a tunnel device, or need
# a phone. It uses no network and no credential.
#
# Usage:
#   scripts/release_audit.sh [--repo-root DIR] [--tag TAG] [--artifacts DIR]
#                            [--require-aligned-versions] [--check-codesign]
#
# Options:
#   --repo-root DIR              Tree to audit. Defaults to this repository.
#   --tag TAG                    Check that the tag matches the engine version.
#   --artifacts DIR              Also audit the release artifacts in DIR.
#   --require-aligned-versions   Treat version drift and every release blocker
#                                as a failure. The release job uses this. A
#                                plain run reports drift and blockers only.
#   --check-codesign             Verify the macOS app signature. Needs macOS.
#                                A packaged app must be ad-hoc signed, not
#                                notarized and not Developer ID.
#
# Output lines start with PASS, WARN, or FAIL. Exit status is 0 when no check
# failed, 1 when a check failed, and 2 on a usage error.

set -eu

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tag=""
artifacts=""
require_aligned=0
check_codesign=0
failures=0
warnings=0
passes=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo-root)
      [ $# -ge 2 ] || { echo "--repo-root needs a directory" >&2; exit 2; }
      root=$(CDPATH= cd -- "$2" && pwd)
      shift 2
      ;;
    --tag)
      [ $# -ge 2 ] || { echo "--tag needs a value" >&2; exit 2; }
      [ -n "$2" ] || { echo "--tag needs a nonempty value" >&2; exit 2; }
      tag=$2
      shift 2
      ;;
    --artifacts)
      [ $# -ge 2 ] || { echo "--artifacts needs a directory" >&2; exit 2; }
      artifacts=$2
      shift 2
      ;;
    --require-aligned-versions) require_aligned=1; shift ;;
    --check-codesign) check_codesign=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

pass() {
  passes=$((passes + 1))
  printf 'PASS  %s\n' "$1"
}

warn() {
  warnings=$((warnings + 1))
  printf 'WARN  %s\n' "$1"
}

fail() {
  failures=$((failures + 1))
  printf 'FAIL  %s\n' "$1"
}

# A release blocker fails a strict audit (--require-aligned-versions) and is a
# warning otherwise. The release job runs the strict form, so a blocker that
# this check cannot verify keeps the release gate closed instead of printing a
# warning beside an exit status of zero.
release_blocker() {
  if [ "$require_aligned" -eq 1 ]; then
    fail "$1"
  else
    warn "$1"
  fi
}

# Verify the shape of the jobs mapping that every exact block comparison
# relies on. A top-level block scalar is valid YAML and can hold a line at the
# job-key indentation that looks like a job header. A scanner that searches the
# whole file would read that decoy and miss the real job. This check rejects a
# top-level block scalar, an ambiguous top-level scalar continuation, a
# case-variant policy key, a duplicate jobs mapping, and a duplicate job
# header. Only one plain `jobs:` mapping may define the jobs.
workflow_job_structure() {
  # Some awk implementations end a record at a NUL byte, so the byte rule in
  # the scan below cannot see one. Count NUL bytes with tr first.
  if [ "$(LC_ALL=C tr -cd '\000' < "$1" | wc -c | tr -d ' ')" != 0 ]; then
    printf 'FAIL  unsupported NUL byte in the workflow; the scanners read text only\n'
  fi
  LC_ALL=C awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function indent_of(s) { match(s, /^[ \t]*/); return RLENGTH }
    function note(msg) { printf "FAIL  %s\n", msg; bad++ }
    # Remove a trailing comment and report a quoted scalar that stays open.
    # A multi-line quoted scalar can fold a line at the job-key indentation.
    function strip_comment(s,   i, n, c, prev, q, out, ch) {
      out = ""; q = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q == "") {
          if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) break
          if (c == sq || c == dq) {
            prev = (i == 1) ? "" : substr(s, i - 1, 1)
            if (i == 1 || prev ~ /[][{} \t,:?]/) q = c
          }
          out = out c
          continue
        }
        out = out c
        if (q == dq && c == "\\" && i < n) {
          i++
          out = out substr(s, i, 1)
          continue
        }
        if (c == q) q = ""
      }
      SQ_OPEN = q
      return trim(out)
    }
    BEGIN {
      sq = sprintf("%c", 39); dq = sprintf("%c", 34)
      n = split("jobs permissions env defaults name run-name on concurrency", names, " ")
      for (i = 1; i <= n; i++) top_name[names[i]] = 1
      n = split("needs if uses with run permissions jobs env steps secrets", body_names, " ")
      for (i = 1; i <= n; i++) body_name[body_names[i]] = 1
      jobs_seen = 0; in_jobs = 0; block = -1; open_quote = ""
      top_scalar = 0; jobcount = 0; bad = 0
    }
    {
      line = $0
      if (index(line, "\r") > 0) {
        note("unsupported carriage return line break at line " NR "; the structure check reads LF only")
        next
      }
      # YAML also reads NEL, LS, and PS as line breaks. They are multi-byte
      # sequences, so this LF scanner would read the text after one as part
      # of a comment. The reviewed subset is printable ASCII, tab, and LF.
      if (line ~ /[^\t\040-\176]/) {
        note("unsupported byte outside printable ASCII at line " NR "; YAML can read it as a line break")
        next
      }
      if (line ~ /^[ \t]*$/) next
      ind = indent_of(line)
      if (index(substr(line, 1, ind), "\t") > 0) {
        note("unsupported tab indentation at line " NR)
        next
      }
      if (block >= 0) {
        if (ind > block) next
        block = -1
      }
      if (open_quote != "") {
        if (index(line, open_quote) > 0) open_quote = ""
        next
      }
      content = substr(line, ind + 1)
      if (content ~ /^#/) next
      code = strip_comment(content)
      if (SQ_OPEN != "") {
        note("unsupported multi-line quoted scalar at line " NR)
        open_quote = SQ_OPEN
        next
      }
      if (code == "") next
      # A top-level plain scalar can continue on a more indented line. A
      # block scalar is the same hazard with an explicit header.
      if (top_scalar && ind > 0) {
        note("unsafe top-level scalar continuation at line " NR)
        top_scalar = 0
      }
      if (ind == 0) {
        in_jobs = 0
        top_scalar = 0
        p = index(code, ":")
        if (p == 0) {
          note("unsupported top-level entry at line " NR)
          next
        }
        key = trim(substr(code, 1, p - 1))
        val = trim(substr(code, p + 1))
        quoted_key = 0
        if (key ~ /^["\047]/) {
          quoted_key = 1
          qk = substr(key, 2, length(key) - 2)
          if (length(key) < 2 || substr(key, length(key), 1) != substr(key, 1, 1)) {
            note("unsupported quoted top-level key at line " NR)
            next
          }
          key = qk
        }
        lower = tolower(key)
        if ((lower in top_name) && key != lower) {
          note("ambiguous case variant of top-level key at line " NR ": " key)
        } else if (!(key in top_name)) {
          # An unknown top-level key is not workflow structure that this
          # check can review. Fail closed instead of guessing how GitHub
          # reads it.
          note("unsupported top-level key at line " NR ": " key)
        }
        if (val ~ /^[|>][-+0-9]*[ \t]*$/) {
          note("unsafe top-level block scalar at line " NR)
          block = 0
          next
        }
        if (key == "jobs") {
          if (quoted_key) {
            note("unsupported quoted jobs key at line " NR)
            next
          }
          jobs_seen++
          if (jobs_seen > 1) note("duplicate jobs mapping at line " NR)
          if (val != "") {
            note("unsupported inline jobs mapping at line " NR)
            next
          }
          in_jobs = 1
          next
        }
        if (val != "") top_scalar = 1
        next
      }
      if (!in_jobs) {
        # A nested mapping under on, concurrency, permissions, or env is not a
        # job mapping. Its entries cannot define a job.
        next
      }
      if (ind < 2) {
        note("unsupported indentation in the jobs mapping at line " NR)
        next
      }
      if (ind == 2) {
        if (code !~ /^[A-Za-z0-9_-]+:[ \t]*$/) {
          note("unsupported job header at line " NR ": " code)
          next
        }
        id = code
        sub(/:.*$/, "", id)
        lc = tolower(id)
        if (lc in job_lc) {
          note("duplicate job header at line " NR ": " id)
        } else {
          job_lc[lc] = id
          jobcount++
        }
        next
      }
      p = index(code, ":")
      if (p > 0) {
        body = code
        sub(/^[-][ \t]+/, "", body)
        p = index(body, ":")
        if (p > 0) {
          key = trim(substr(body, 1, p - 1))
          lower = tolower(key)
          if ((lower in body_name) && key != lower) {
            note("ambiguous case variant of job key at line " NR ": " key)
          }
        }
      }
    }
    END {
      if (jobs_seen == 0) note("no jobs mapping was found")
      if (jobcount == 0) note("the jobs mapping defines no job")
      if (bad == 0) printf "PASS  the jobs mapping is structurally unambiguous\n"
    }
  ' "$1"
}

# Scan every action reference and every permission grant in one pass. A text
# scanner cannot read every YAML spelling, so an unsupported spelling is a
# failure, not a pass.
#
# The scan reads one reviewed YAML subset: block mappings, block sequences,
# block scalars, single-line quoted scalars, a flow sequence used as a value,
# and a GitHub `${{ }}` expression on one line. Every other construct fails
# closed: explicit keys, a flow collection in a node position, a flow mapping in
# a value, YAML tags, anchors, aliases, merge keys, multi-line quoted scalars,
# and tab indentation. A quote that stays open on its line is rejected because
# a multi-line quoted scalar can hold text at any indentation, including a fake
# block-scalar header. These rules exist so that a valid YAML spelling cannot
# hide an action reference or a permission grant from review. The scan also
# rejects a workflow-level defaults mapping, a workflow-level env entry that is
# not inert, a duplicate top-level key, a duplicate job id, a YAML document
# marker or directive, and an expression that spans lines.
workflow_scan_policy() {
  LC_ALL=C awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function indent_of(s) { match(s, /^[ \t]*/); return RLENGTH }
    function note(msg) { printf "FAIL  %s\n", msg }
    function quoted_close(s, start, q,   j, n, ch, esc) {
      n = length(s); esc = 0; QC_ESCAPED = 0
      for (j = start + 1; j <= n; j++) {
        ch = substr(s, j, 1)
        if (q == dq) {
          if (esc) { esc = 0; continue }
          if (ch == "\\") { esc = 1; QC_ESCAPED = 1; continue }
          if (ch == dq) return j
        } else if (ch == sq) {
          if (substr(s, j + 1, 1) == sq) { j++; continue }
          return j
        }
      }
      return 0
    }
    # Remove a trailing comment and reject a quote that stays open. SL_CODE
    # holds the text the scan reads. SL_MASK is the same text with every quoted
    # segment masked, so a quoted word cannot look like a key. A quote opens a
    # scalar only at the start of a token, so an apostrophe inside a plain word
    # is not a quote.
    function scan_line(s,   i, n, c, prev, j, out, mask, seg, m, rep) {
      n = length(s); out = ""; mask = ""; i = 1
      SL_QUOTE = ""; SL_ESCAPE = 0
      while (i <= n) {
        c = substr(s, i, 1)
        if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) break
        if (c == dq || c == sq) {
          prev = (i == 1) ? "" : substr(s, i - 1, 1)
          if (!(i == 1 || prev ~ /[][{} \t,:?]/)) { out = out c; mask = mask c; i++; continue }
          j = quoted_close(s, i, c)
          if (j == 0) { SL_QUOTE = c; return 0 }
          if (QC_ESCAPED) SL_ESCAPE = 1
          seg = substr(s, i, j - i + 1)
          out = out seg
          rep = ""
          for (m = 1; m <= length(seg); m++) rep = rep "x"
          mask = mask rep
          i = j + 1
          continue
        }
        out = out c
        mask = mask c
        i++
      }
      SL_CODE = trim(out)
      SL_MASK = trim(mask)
      return 1
    }
    # Find a mapping separator: a colon followed by space, tab, or end of line.
    function colon_sep(s,   i, n, c, j) {
      n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == dq || c == sq) {
          j = quoted_close(s, i, c)
          if (j == 0) return 0
          i = j
          continue
        }
        if (c == ":" && (i == n || substr(s, i + 1, 1) ~ /[ \t]/)) return i
      }
      return 0
    }
    # Parse one block entry into PE_KEY and PE_VAL. A quoted value is unquoted.
    function parse_entry(s,   p, k, v, rest, e) {
      PE_OK = 0; PE_KEY = ""; PE_VAL = ""; PE_TAIL = ""; PE_QKEY = 0; PE_QVAL = 0
      if (s ~ /^-[ \t]+/) { match(s, /^-[ \t]+/); s = substr(s, RLENGTH + 1) }
      if (s == "") return 0
      if (substr(s, 1, 1) == dq || substr(s, 1, 1) == sq) {
        e = quoted_close(s, 1, substr(s, 1, 1))
        if (e == 0) return 0
        rest = substr(s, e + 1)
        if (rest !~ /^[ \t]*:/) return 0
        PE_KEY = substr(s, 2, e - 2)
        PE_QKEY = 1
        sub(/^[ \t]*:/, "", rest)
        v = trim(rest)
      } else {
        p = colon_sep(s)
        if (p == 0) return 0
        k = substr(s, 1, p - 1)
        sub(/[ \t]+$/, "", k)
        PE_KEY = k
        v = trim(substr(s, p + 1))
      }
      PE_OK = 1
      if (substr(v, 1, 1) == dq || substr(v, 1, 1) == sq) {
        e = quoted_close(v, 1, substr(v, 1, 1))
        if (e > 0) {
          PE_QVAL = 1
          PE_VAL = substr(v, 2, e - 2)
          rest = substr(v, e + 1)
          if (rest !~ /^[ \t]*$/) PE_TAIL = trim(rest)
        } else {
          PE_VAL = v
        }
      } else {
        PE_VAL = v
      }
      return 1
    }
    function record_write(jb, sc, ln) {
      writes++
      w_job[writes] = jb
      w_scope[writes] = sc
      w_line[writes] = ln
    }
    # A job or step mapping may not repeat a key. GitHub can read the last
    # value, so a duplicate steps, run, with, or needs key can hide a command
    # from a scanner that read the first value.
    function clear_step_keys(   k) {
      for (k in step_key_seen) delete step_key_seen[k]
    }
    # Finish the step that a sequence item started. An upload step must carry a
    # retention limit in its own `with:` mapping.
    function finish_step(   owner) {
      if (step_upload) {
        if (!step_retention) {
          note("an uploaded artifact has no retention limit at line " step_line)
          uploads_missing++
        }
        if (step_name == "") {
          note("an upload step has no reviewed artifact name at line " step_line)
          step_name_bad = 1
        } else if (!(step_name in artifact_owner)) {
          note("artifact name is not in the reviewed upload allowlist: " step_name)
          step_name_bad = 1
        } else if (artifact_owner[step_name] != step_job) {
          note("artifact " step_name " may be uploaded only by job " artifact_owner[step_name])
          step_name_bad = 1
        }
        if (step_name in upload_seen) {
          note("artifact name is uploaded more than once: " step_name)
          step_name_bad = 1
        } else if (step_name != "") {
          upload_seen[step_name] = 1
        }
        if (step_overwrite) {
          note("an upload step may overwrite an existing artifact: " step_name)
          step_name_bad = 1
        }
      }
      # A setup action can restore a dependency cache through a `cache` input.
      # That restore has no tag guard, so a poisoned cache entry could reach a
      # tag build. Only the tag-guarded rust-cache step may take a cache input.
      if (step_cache_key && !step_rust_cache) {
        note("a step enables a dependency cache without the tag guard at line " step_cache_line)
        cache_bad = 1
      }
      step_upload = 0; step_retention = 0; in_with = -1; step_line = 0
      step_name = ""; step_overwrite = 0
      step_cache_key = 0; step_cache_line = 0; step_rust_cache = 0
      clear_step_keys()
    }
    # GitHub expressions run inside block scalars too, so read every line. Any
    # expression that names the secrets context fails, including a bare
    # `secrets` object and `toJSON(secrets)`. A line-at-a-time scan cannot read
    # an expression that opens on one line and closes on another, so reject
    # that spelling instead of guessing where the expression ends.
    function check_expression(s, ln,   lower, start, rest, stop, pos) {
      lower = tolower(s)
      pos = 1
      while ((start = index(substr(lower, pos), "${{")) > 0) {
        start = pos + start - 1
        rest = substr(lower, start + 3)
        stop = index(rest, "}}")
        if (stop == 0) {
          note("unsupported multi-line expression at line " ln)
          secret_bad = 1
          return
        }
        pos = start + 3 + stop + 1
      }
      if (!match(lower, /\$\{\{/)) return
      lower = substr(lower, RSTART + 3)
      if (lower ~ /(^|[^A-Za-z0-9_.-])secrets([^A-Za-z0-9_-]|$)/) {
        note("ci.yml reads a repository secret at line " ln)
        secret_bad = 1
      }
    }
    function handle_inline(v, top,   vv) {
      vv = tolower(v)
      if (vv == "write-all") { note("the workflow grants write-all permissions"); return }
      if (vv == "read-all") { if (top) top_read_all = 1; return }
      if (vv == "{}") { if (top) top_read_all = 1; return }
      if (v ~ /[{}]/) {
        if (tolower(v) ~ /write/) note("an inline permissions mapping grants write access")
        else note("unsupported inline permissions mapping")
        return
      }
      note("unsupported permissions value: " v)
    }
    # A reviewed trigger is one exact lower-case name. A case variant can hide
    # pull_request_target from a text match, and an unknown trigger is not a
    # policy this scanner can review.
    function check_trigger_token(t, ln,   lc, q) {
      t = trim(t)
      if (t == "") { note("empty trigger at line " ln); trigger_bad = 1; return }
      q = substr(t, 1, 1)
      if (q == dq || q == sq) {
        if (length(t) < 2 || substr(t, length(t), 1) != q) {
          note("unsupported trigger spelling at line " ln)
          trigger_bad = 1
          return
        }
        t = substr(t, 2, length(t) - 2)
      }
      if (t ~ /[][{}:,]/ || index(t, " ") > 0 || index(t, "\t") > 0) {
        note("unsupported trigger spelling at line " ln)
        trigger_bad = 1
        return
      }
      lc = tolower(t)
      if (lc == "pull_request_target") {
        note("the workflow uses pull_request_target at line " ln)
        trigger_bad = 1
        return
      }
      if (t != lc) {
        note("ambiguous case variant of trigger " t " at line " ln)
        trigger_bad = 1
        return
      }
      if (!(t in trigger_allowed)) {
        note("unsupported trigger " t " at line " ln)
        trigger_bad = 1
        return
      }
      if (t in trigger_seen) {
        note("duplicate trigger " t " at line " ln)
        trigger_bad = 1
        return
      }
      trigger_seen[t] = 1
    }
    function check_trigger_list(v, ln,   s, count, parts, i, t) {
      s = trim(v)
      if (substr(s, 1, 1) == "[") {
        if (substr(s, length(s), 1) != "]") {
          note("unsupported trigger list at line " ln)
          trigger_bad = 1
          return
        }
        s = substr(s, 2, length(s) - 2)
        count = split(s, parts, ",")
      } else {
        count = 1
        parts[1] = s
      }
      for (i = 1; i <= count; i++) {
        t = trim(parts[i])
        if (t == "") {
          if (count == 1) { note("empty trigger at line " ln); trigger_bad = 1 }
          continue
        }
        check_trigger_token(t, ln)
      }
    }
    BEGIN {
      sq = sprintf("%c", 39); dq = sprintf("%c", 34)
      n = split("actions attestations checks contents deployments discussions id-token issues packages pages pull-requests repository-projects security-events statuses models", scopes, " ")
      for (i = 1; i <= n; i++) scope[scopes[i]] = 1
      # A workflow-level env entry is inherited by every job, including the
      # release and verification jobs. Only names that cannot change command
      # lookup, shell startup, or the loader may appear there.
      n = split("CARGO_TERM_COLOR RUST_BACKTRACE", env_names, " ")
      for (i = 1; i <= n; i++) env_allowed[env_names[i]] = 1
      # An exact owner/repository and commit SHA allowlist. A full SHA alone
      # does not prove that the reviewed action is the one that runs: a fork
      # can keep the same repository name, and another repository can offer a
      # different action at a fixed SHA. Names compare case-insensitively, as
      # GitHub compares them.
      n = split("actions/checkout@11d5960a326750d5838078e36cf38b85af677262 actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9 Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 microsoft/setup-msbuild@6fb02220983dee41ce7ae257b6f4d8f9bf5ed4ce android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407", action_names, " ")
      for (i = 1; i <= n; i++) action_allowed[tolower(action_names[i])] = 1
      # An artifact name may be uploaded by one job only. A later upload of
      # the same name either fails (v4 default) or replaces verified bytes
      # when overwrite is on. The release job downloads release-bundle by
      # name, so the name must belong to the reviewed integrity job.
      n = split("hotspotshade-macos-arm64:rust-macos HotspotShade-iOS-unsigned-ipa:ios HotspotShade-macos-unsigned:macos-app release-bundle:artifact-integrity", artifact_pairs, " ")
      for (i = 1; i <= n; i++) {
        split(artifact_pairs[i], pair, ":")
        artifact_owner[pair[1]] = pair[2]
      }
      # These names can change command lookup, the compiler driver, the
      # dynamic loader, or a shell startup file. A job or step env entry with
      # one of them can replace a reviewed command without changing it. Windows
      # environment names are case-insensitive, and Path and PATHEXT choose the
      # command that runs there, so a case variant must fail too.
      n = split("PATH BASH_ENV ENV SHELL LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH RUSTC_WRAPPER RUSTC RUSTFLAGS CARGO_BUILD_RUSTC_WRAPPER CC CXX AR CARGO_HOME RUSTUP_TOOLCHAIN PATHEXT COMSPEC", env_blocked, " ")
      for (i = 1; i <= n; i++) env_forbidden[tolower(env_blocked[i])] = 1
      # These keys change policy when GitHub reads them case-insensitively.
      # Reject a case variant instead of guessing which spelling runs.
      n = split("jobs permissions env defaults name on concurrency needs if uses with run steps secrets retention-days overwrite artifacts environment outputs shell container services continue-on-error pull_request_target", policy_keys, " ")
      for (i = 1; i <= n; i++) policy_key[policy_keys[i]] = 1
      # The workflow may use only these triggers. pull_request_target is never
      # reviewed, and a case variant of any trigger fails closed.
      n = split("push pull_request workflow_dispatch", triggers, " ")
      for (i = 1; i <= n; i++) trigger_allowed[triggers[i]] = 1
      job = ""; in_jobs = 0; perm = -1; perm_job = ""; perm_ctx = ""
      block = -1; open_quote = ""
      writes = 0; top_seen = 0; top_read = 0; top_read_all = 0; top_write = 0
      total = 0; pinned = 0; pin_bad = 0; allow_bad = 0
      uploads = 0; uploads_retained = 0; uploads_missing = 0
      step_upload = 0; step_retention = 0; step_line = 0; in_with = -1
      step_job = ""; step_name = ""; step_overwrite = 0
      step_name_bad = 0; job_body_ind = -1
      secret_bad = 0; anchor_bad = 0; retention_bad = 0
      env_top = -1; env_bad = 0; defaults_bad = 0; duplicate_bad = 0
      env_entry_ind = -1
      cache_guard_pending = 0; cache_bad = 0; case_bad = 0
      step_cache_key = 0; step_cache_line = 0; step_rust_cache = 0
      environment_bad = 0
      cache_guard_ind = -1; guard_line = 0; condition_bad = 0
      step_key_ind = -1; step_dash_ind = -1; shell_bad = 0
      map_bad = 0; plain_bad = 0; plain_ind = -1
      on_ind = -1; trigger_bad = 0; continue_bad = 0
    }
    {
      line = $0
      # YAML reads a lone CR as a line break. The scan reads LF only, so a CR
      # would hide the text that follows it. Reject every CR rather than guess.
      if (index(line, "\r") > 0) {
        note("unsupported carriage return line break at line " NR "; the scan reads LF line breaks only")
        next
      }
      if (line ~ /^[ \t]*$/) next
      # Expressions are evaluated inside block scalars, so this check runs
      # before the block skip and before comment removal.
      check_expression(line, NR)
      # NEL, LS, and PS are YAML line breaks. Reject every byte outside
      # printable ASCII and tab, after the expression check has read the line.
      if (line ~ /[^\t\040-\176]/) {
        note("unsupported byte outside printable ASCII at line " NR "; YAML can read it as a line break")
        next
      }
      ind = indent_of(line)
      if (index(substr(line, 1, ind), "\t") > 0) {
        note("unsupported tab indentation at line " NR)
        next
      }
      if (block >= 0) {
        if (ind > block) next
        block = -1
      }
      if (open_quote != "") {
        if (index(line, open_quote) > 0) open_quote = ""
        next
      }
      content = substr(line, ind + 1)
      if (content ~ /^#/) next
      # A plain YAML scalar can continue on a more indented line, and the shell
      # runs the joined text. A line-at-a-time scan would miss the rest of the
      # value. A block scalar is the reviewed spelling for multi-line text.
      if (plain_ind >= 0) {
        if (ind > plain_ind) {
          note("unsupported plain scalar continuation at line " NR "; the scan reads one line per plain value")
          plain_bad = 1
          next
        }
        plain_ind = -1
      }
      if (!scan_line(content)) {
        note("unsupported multi-line quoted scalar at line " NR "; the scan reads single-line quotes only")
        open_quote = SL_QUOTE
        next
      }
      if (SL_ESCAPE) {
        note("unsupported YAML escape in a quoted value at line " NR "; escapes can spell an expression or a trigger")
      }
      code = SL_CODE
      if (code == "") next
      # A second YAML document could make the scan and GitHub read different
      # trees. A directive can change how the rest of the document is parsed.
      if (code == "---" || code == "...") {
        note("unsupported YAML document marker at line " NR)
        next
      }
      if (code ~ /^%/) {
        note("unsupported YAML directive at line " NR)
        next
      }

      # A restored cache can carry compiled output into a tag build. Every
      # cache step must be disabled on a tag, and the guard must be the next
      # code line after the action reference, at the step mapping indentation,
      # so a later key cannot reorder it and a line outside the step cannot
      # supply it.
      if (cache_guard_pending) {
        guard = "if: github.ref_type != " sq "tag" sq
        if (code != guard || ind != cache_guard_ind) {
          note("a cache step lacks the tag guard at line " NR)
          cache_bad = 1
        } else {
          guard_line = NR
        }
        cache_guard_pending = 0
      }

      # The key column of this line: past the sequence dash when it has one.
      key_ind = ind
      if (code ~ /^-[ \t]+/) { match(code, /^-[ \t]+/); key_ind = ind + RLENGTH }

      # A sequence item starts a step. It also starts a block list item in
      # `needs:`, which cannot carry an upload, so the reset is harmless. A
      # lone dash starts a step whose mapping begins on the next line. Track
      # the key column of the step mapping, so a `uses` or a guard nested in
      # `with:` or `env:` cannot pass for a step key.
      if (code ~ /^-([ \t]|$)/) {
        finish_step()
        step_job = job
        step_dash_ind = ind
        step_key_ind = (code ~ /^-[ \t]+[^ \t]/) ? key_ind : -2
      } else if (step_dash_ind >= 0 && ind <= step_dash_ind) {
        step_key_ind = -1; step_dash_ind = -1
      } else if (step_key_ind == -2) {
        step_key_ind = ind
      }

      t = code
      sub(/^-[ \t]+/, "", t)
      if (t ~ /^\?([ \t]|$)/) { note("unsupported YAML explicit key at line " NR); next }
      if (t ~ /^[[{]/) { note("unsupported YAML flow collection at line " NR); next }
      if (t ~ /^!/) { note("unsupported YAML tag at line " NR); next }
      if (t ~ /^[&*]/) { note("unsupported YAML anchor or alias at line " NR); next }
      if (t ~ /^<<[ \t]*:/) { note("unsupported YAML merge key at line " NR); next }

      have = parse_entry(code)
      if (have && index(PE_KEY, "\\") > 0) {
        note("unsupported YAML escape in a key at line " NR)
        have = 0
      }
      # A quoted or spaced merge key is still a merge key. Reject it after
      # parsing so the quote cannot hide the merge from the line-level check.
      if (have && PE_KEY == "<<") {
        note("unsupported YAML merge key at line " NR)
        have = 0
      }
      # YAML keys are case-sensitive, but a policy that assumed that would
      # depend on how GitHub treats a case variant. Reject the variant.
      if (have) {
        lc_key = tolower(PE_KEY)
        if ((lc_key in policy_key) && PE_KEY != lc_key) {
          note("ambiguous case variant of the policy key " PE_KEY " at line " NR)
          case_bad = 1
        }
        # These keys are never allowed, in any case spelling. A case variant
        # is also reported by the policy-key check above, but the explicit
        # check keeps the fail message and the exact spelling covered.
        if (lc_key == "continue-on-error") {
          note("the workflow uses continue-on-error at line " NR)
          continue_bad = 1
        }
        if (lc_key == "pull_request_target") {
          note("the workflow uses pull_request_target at line " NR)
          trigger_bad = 1
        }
      }
      # A step mapping may not repeat a key. GitHub can read the last value, so
      # a second run, uses, with, or if key can hide a command or an input from
      # a scanner that read the first value.
      if (have && step_key_ind >= 0 && key_ind == step_key_ind) {
        sk = PE_KEY
        if (sk in step_key_seen) {
          note("duplicate key " sk " in a step at line " NR)
          map_bad = 1
        } else {
          step_key_seen[sk] = 1
        }
      }

      # A duplicate top-level key is ambiguous. Some YAML readers keep the
      # first value and some keep the last, so a policy check and GitHub could
      # read different trees. Fail closed.
      # A top-level key ends any trigger mapping. The one `on` value is read
      # below, including an inline list. A duplicate `on` key is already an
      # error, so a second value cannot replace the reviewed trigger set.
      if (ind == 0) on_ind = -1
      if (ind == 0 && have) {
        if (PE_KEY in top_keys) {
          note("duplicate top-level key at line " NR ": " PE_KEY)
          duplicate_bad = 1
        } else {
          top_keys[PE_KEY] = 1
        }
        if (PE_KEY == "on") {
          if (PE_VAL == "" && !PE_QVAL) {
            on_ind = ind
            for (k in trigger_seen) delete trigger_seen[k]
          } else {
            check_trigger_list(PE_VAL, NR)
          }
        }
        # Workflow-level defaults can replace the shell or the working
        # directory of every run step, including the release and verification
        # steps. The reviewed job blocks would still match, so reject the key
        # rather than hide that change from the block comparison.
        if (PE_KEY == "defaults") {
          note("workflow-level defaults are not allowed at line " NR)
          defaults_bad = 1
        }
        # A top-level block scalar can hold a line at the job-key indentation.
        # The structure check rejects it; keep this scan from reading the body
        # as workflow structure as well.
        if (!PE_QVAL && PE_VAL ~ /^[|>][-+0-9]*[ \t]*$/) {
          note("unsafe top-level block scalar at line " NR)
          duplicate_bad = 1
        }
      }

      # Read the direct children of the one `on` mapping. Nested keys are
      # filters, not trigger names. A sequence item or a mapping key at the
      # wrong indentation fails closed instead of hiding a trigger.
      if (on_ind >= 0 && ind > on_ind) {
        if (ind == on_ind + 2) {
          if (code ~ /^-([ \t]|$)/) {
            trigger_value = code
            sub(/^-[ \t]*/, "", trigger_value)
            if (trigger_value ~ /:/) {
              note("unsupported trigger entry at line " NR)
              trigger_bad = 1
            } else {
              check_trigger_token(trigger_value, NR)
            }
          } else if (have) {
            if (PE_VAL != "" || PE_QVAL) {
              note("unsupported trigger mapping value at line " NR)
              trigger_bad = 1
            } else {
              check_trigger_token(PE_KEY, NR)
            }
          } else {
            note("unsupported trigger entry at line " NR)
            trigger_bad = 1
          }
        } else if (ind == on_ind + 1) {
          note("unsupported trigger indentation at line " NR)
          trigger_bad = 1
        }
      }

      # The first key after a job header belongs to the job mapping. A
      # job-level `uses` key is a reusable workflow, not a step, and cannot
      # carry the reviewed commands. Reject it instead of counting it as a
      # pinned action.
      if (job != "" && ind > 2 && have) {
        if (job_body_ind < 0) job_body_ind = ind
        if (PE_KEY == "uses" && ind == job_body_ind) {
          note("job-level reusable workflow is not allowed at line " NR)
          pin_bad = 1
        }
        # A job mapping may not repeat a key. GitHub can read the last value,
        # so a second steps, needs, or permissions key can hide a command or a
        # dependency from a scanner that read the first value.
        if (ind == job_body_ind) {
          jk = job SUBSEP PE_KEY
          if (jk in job_key_seen) {
            note("duplicate key " PE_KEY " in job " job " at line " NR)
            map_bad = 1
          } else {
            job_key_seen[jk] = 1
          }
        }
      }

      # A condition can skip a test step or a whole job and leave it green. The
      # only conditions allowed are the cache tag guard, read above, and the
      # job-level tag condition of the release job, which its exact block pins.
      if (have && tolower(PE_KEY) == "if" && guard_line != NR) {
        if (!(job == "release" && ind == job_body_ind)) {
          note("a condition can skip a step or job at line " NR)
          condition_bad = 1
        }
      }

      # A shell override or a job-level `defaults`, `container`, or `services`
      # key can replace or wrap every command of a step or job and still leave
      # it green. The workflow uses `shell: bash` only.
      if (have && PE_KEY == "shell") {
        if (PE_VAL != "bash" || PE_QVAL || PE_TAIL != "") {
          note("a shell other than bash can replace a command at line " NR)
          shell_bad = 1
        }
      }
      if (have && job != "" && ind == job_body_ind && (PE_KEY == "defaults" || PE_KEY == "container" || PE_KEY == "services")) {
        note("job-level " PE_KEY " can replace or wrap every step at line " NR)
        shell_bad = 1
      }

      # A deployment environment gates the release token and any environment
      # secret. Only the release job may name one, and only `release`, at the
      # job level. Another job that names it would bypass the reviewed block.
      if (have && PE_KEY == "environment") {
        if (job != "release" || ind != job_body_ind || PE_VAL != "release" || PE_QVAL || PE_TAIL != "") {
          note("only the release job may use the release environment, at line " NR)
          environment_bad = 1
        }
      }

      # Workflow-level env is inherited by every job. An entry such as PATH,
      # BASH_ENV, LD_PRELOAD, or GH_HOST can replace a command or redirect the
      # release client without changing any reviewed job block. Only an inert
      # allowlist may appear here.
      is_env_header = (ind == 0 && have && PE_KEY == "env")
      if (is_env_header) {
        if (PE_VAL != "" || PE_QVAL) {
          note("unsupported workflow-level env mapping at line " NR)
          env_bad = 1
          env_top = -1
        } else {
          env_top = ind
        }
      } else if (env_top >= 0) {
        if (ind <= env_top) {
          env_top = -1
        } else if (!have) {
          note("unsupported workflow-level env entry at line " NR)
          env_bad = 1
        } else if (!(PE_KEY in env_allowed)) {
          note("workflow-level env may not set " PE_KEY " at line " NR)
          env_bad = 1
        } else if (PE_TAIL != "") {
          note("unsupported workflow-level env value at line " NR)
          env_bad = 1
        }
      }
      # A job or step env entry can replace the compiler, the loader, a shell
      # startup file, or a command path. Exact job blocks cover the release
      # path; this check covers every other job as well. Only an entry inside
      # an env mapping is an environment variable. The name is compared without
      # case because Windows reads environment names that way.
      if (env_entry_ind >= 0 && ind <= env_entry_ind) env_entry_ind = -1
      if (have && PE_KEY == "env" && PE_VAL == "" && !PE_QVAL &&
          (ind == 0 || ind == job_body_ind || ind == step_key_ind)) {
        env_entry_ind = ind
      }
      if (have && env_entry_ind >= 0 && ind > env_entry_ind) {
        env_key_lc = tolower(PE_KEY)
        if (env_key_lc in env_forbidden) {
          note("environment variable " PE_KEY " may replace a command at line " NR)
          env_bad = 1
        }
      }

      # A flow mapping can carry an action or a permission inside a value. A
      # GitHub expression uses braces too, so remove `${{` and `}}` first. A
      # permissions line keeps its own check, which names the write grant.
      mask = SL_MASK
      if (!(have && PE_KEY == "permissions")) {
        gsub(/\$[{][{]/, "", mask)
        gsub(/[}][}]/, "", mask)
        if (index(mask, "{") > 0 || index(mask, "}") > 0) {
          note("unsupported YAML flow mapping at line " NR)
          next
        }
      }

      # An anchor or alias in a value can move text that the scan reads for a
      # key. Reject one at the start of a token. A shell `2>&1`, a glob after a
      # slash, and a quoted word do not match this shape.
      if (SL_MASK ~ /(^|[ \t:,\[-])[&*][A-Za-z0-9_-]+/) {
        note("unsupported YAML anchor or alias in a value at line " NR)
        anchor_bad = 1
      }

      # A reusable workflow inherits every repository secret through
      # `secrets: inherit`. Reject the key in any spelling the scan parses.
      if (have && PE_KEY == "secrets") {
        note("the workflow passes secrets to a reusable workflow at line " NR)
        secret_bad = 1
      }

      # A quoted word is masked, so this match only sees a real key spelling.
      if (SL_MASK ~ /(^|[^A-Za-z0-9_-])["]?uses["]?[ \t]*:/ && !(have && PE_KEY == "uses")) {
        note("unsupported YAML spelling for an action reference at line " NR)
        pin_bad = 1
      }
      if (have && PE_KEY == "uses") {
        total++
        v = PE_VAL
        if (key_ind != step_key_ind) {
          # A `uses` key nested in `with:` or `env:` is an input, not an
          # action. Counting it would let it pass for a guarded cache step.
          note("action reference outside a step mapping at line " NR)
          pin_bad = 1
        } else if (PE_TAIL != "" || v == "" || v ~ /[ \t]/ || index(v, dq) > 0 || index(v, sq) > 0) {
          note("unsupported or empty action reference at line " NR)
          pin_bad = 1
        } else {
          vv = tolower(v)
          if (!(vv in action_allowed)) {
            note("action reference is not in the reviewed allowlist at line " NR ": " v)
            pin_bad = 1
            allow_bad = 1
          }
          if (vv ~ /^actions\/upload-artifact@/) {
            uploads++
            step_upload = 1
            step_line = NR
          } else if (vv ~ /upload/) {
            note("unsupported artifact upload action at line " NR ": " v)
            retention_bad = 1
          }
          if (vv ~ /^swatinem\/rust-cache@/) {
            cache_guard_pending = 1; step_rust_cache = 1
            # The guard belongs to this step mapping, at its key column.
            cache_guard_ind = key_ind
          }
          parts_n = split(v, parts, "@")
          if (parts_n == 2 && parts[1] != "" && parts[2] ~ /^[0-9a-f]+$/ && length(parts[2]) == 40) {
            pinned++
          } else {
            note("action reference is not pinned to a full commit SHA at line " NR ": " v)
            pin_bad = 1
          }
        }
      }

      # Track a `with:` mapping on an upload step and its retention limit.
      if (have && PE_KEY == "with") {
        if (PE_VAL == "" && !PE_QVAL) {
          in_with = key_ind
        } else {
          note("unsupported inline with mapping at line " NR)
          in_with = -1
          retention_bad = 1
        }
      }
      if (in_with >= 0 && ind <= in_with && !(have && PE_KEY == "with")) in_with = -1
      # Record a `with:` name before or after the upload action reference, so
      # the order of the keys cannot hide an artifact name. Only an upload
      # step uses the value; a download `name` is ignored at the end of the
      # step. An overwrite key is rejected wherever it appears.
      if (in_with >= 0 && ind > in_with && have) {
        if (PE_KEY == "name") {
          if (step_name != "") {
            note("a step has more than one with name at line " NR)
            step_name_bad = 1
          } else if (PE_TAIL != "" || PE_VAL == "" || PE_VAL ~ /[ \t]/) {
            note("unsupported artifact name at line " NR)
            step_name_bad = 1
          } else {
            step_name = PE_VAL
          }
        }
        # GitHub passes an input name to the action without case, so
        # `Cache:` is the same input as `cache:`.
        lk = tolower(PE_KEY)
        if (lk ~ /^cache/ || lk == "package-manager-cache") {
          step_cache_key = 1
          if (!step_cache_line) step_cache_line = NR
        }
        if (PE_KEY == "overwrite") {
          note("an artifact upload may overwrite an existing artifact at line " NR)
          step_overwrite = 1
          step_name_bad = 1
        }
      }
      if (have && PE_KEY == "retention-days") {
        if (step_upload && in_with >= 0 && ind > in_with) {
          if (step_retention) {
            note("an upload step has more than one retention limit at line " NR)
            retention_bad = 1
          } else if (PE_TAIL != "" || PE_QVAL || PE_VAL !~ /^[0-9]+$/) {
            note("unsupported retention value at line " NR)
            retention_bad = 1
          } else {
            step_retention = 1
            uploads_retained++
          }
        } else {
          note("retention-days outside an upload step at line " NR)
          retention_bad = 1
        }
      }

      # A flow sequence can carry a single mapping pair, e.g. `["uses": x]`.
      # The quoted key is masked, so inspect the brackets and reject a colon
      # that sits inside them. A plain list such as `[main]` still passes. An
      # unquoted `[uses: x]` already fails the spelling check above.
      if (index(mask, "[") > 0 || index(mask, "]") > 0) {
        depth = 0; flow_bad = 0
        for (fi = 1; fi <= length(mask); fi++) {
          fc = substr(mask, fi, 1)
          if (fc == "[") depth++
          else if (fc == "]") { if (depth == 0) flow_bad = 1; else depth-- }
          else if (fc == ":" && depth > 0) flow_bad = 1
        }
        if (depth != 0) flow_bad = 1
        if (flow_bad) {
          note("unsupported YAML flow mapping in a sequence at line " NR)
          next
        }
      }

      if (perm >= 0 && ind <= perm) perm = -1
      if (perm >= 0) {
        if (!have) { note("unsupported permission entry at line " NR); next }
        k = PE_KEY; v = PE_VAL
        if (!(k in scope)) { note("unknown permission scope at line " NR ": " k); next }
        if (PE_TAIL != "" || v ~ /[][{}]/ || v ~ /[ \t]/) { note("unsupported permission value at line " NR); next }
        vv = tolower(v)
        if (vv == "write") {
          record_write(perm_job, k, NR)
          if (perm_ctx == "top") top_write = 1
        } else if (vv != "read" && vv != "none") {
          note("unsupported permission value at line " NR ": " v)
        } else if (perm_ctx == "top" && k == "contents") {
          top_read = 1
        }
        next
      }

      if (ind == 0) {
        if (have && PE_KEY == "jobs") { in_jobs = 1; job = "" } else { in_jobs = 0; job = "" }
      } else if (in_jobs && ind == 2) {
        if (have && PE_VAL == "" && !PE_QVAL) {
          job = PE_KEY
          job_body_ind = -1
          if (job in job_seen) {
            note("duplicate job id at line " NR ": " job)
            duplicate_bad = 1
          } else {
            job_seen[job] = 1
          }
        } else { note("unsupported job header at line " NR); job = "" }
      } else if (in_jobs && ind == 4) {
        if (!have) note("unsupported job body entry at line " NR)
      }

      if (have && PE_KEY == "jobs" && ind == 0 && PE_VAL != "") note("unsupported inline jobs mapping at line " NR)
      if (have && PE_KEY == "permissions") {
        if (ind == 0) { perm_ctx = "top"; perm_job = ""; top_seen = 1 }
        else if (job != "") { perm_ctx = "job"; perm_job = job }
        else { note("permissions mapping outside a job at line " NR); next }
        if (PE_VAL == "" && !PE_QVAL) perm = ind
        else handle_inline(PE_VAL, perm_ctx == "top")
      }

      if (have && PE_VAL != "" && !PE_QVAL && PE_TAIL == "" &&
          PE_VAL !~ /^[|>][-+0-9]*[ \t]*$/) {
        plain_ind = key_ind
      }

      off = 0
      if (code ~ /^-[ \t]+/) { match(code, /^-[ \t]+/); off = RLENGTH }
      bt = substr(code, off + 1)
      if (bt ~ /:[ \t]*[|>][-+0-9]*[ \t]*$/ || (off > 0 && bt ~ /^[|>][-+0-9]*[ \t]*$/)) block = ind + off
    }
    END {
      if (total == 0) {
        note("no action reference was found in the workflow")
      } else if (pinned == total && !pin_bad) {
        printf "PASS  every action is pinned to a full commit SHA (%d references)\n", total
      } else if (pinned != total) {
        note(sprintf("%d of %d actions are not pinned to a full commit SHA", total - pinned, total))
      } else {
        note("an action reference could not be read; the pin check fails closed")
      }
      if (!allow_bad && total > 0) {
        printf "PASS  every action reference matches the reviewed owner and SHA allowlist\n"
      }

      if (writes == 0) {
        note("the release job does not grant contents: write")
      } else {
        ok = 1
        for (i = 1; i <= writes; i++) {
          if (w_job[i] != "release" || w_scope[i] != "contents") {
            ok = 0
            note(sprintf("job %s grants %s: write; only the release job may grant contents: write", (w_job[i] == "" ? "<top-level>" : w_job[i]), w_scope[i]))
          }
        }
        if (writes > 1) {
          ok = 0
          note(sprintf("%d write permission entries found; exactly one contents: write entry is allowed", writes))
        }
        if (ok) printf "PASS  only the release job grants contents: write\n"
      }
      if (top_seen && !top_write && (top_read || top_read_all)) {
        printf "PASS  the default token is read only\n"
      } else {
        note("the default token is not read only")
      }

      finish_step()
      if (cache_guard_pending) {
        note("a cache step lacks the tag guard at end of file")
        cache_bad = 1
      }
      if (!cache_bad) {
        printf "PASS  every cache step is disabled on a tag build\n"
      }
      if (!shell_bad) {
        printf "PASS  no step or job overrides the shell, the defaults, or the runner container\n"
      }
      if (!condition_bad) {
        printf "PASS  no step or job has a condition other than the reviewed guards\n"
      }
      if (!map_bad) {
        printf "PASS  no job or step mapping repeats a key\n"
      }
      if (!plain_bad) {
        printf "PASS  no plain scalar continues on a more indented line\n"
      }
      if (!environment_bad) {
        printf "PASS  only the release job names a deployment environment\n"
      }
      if (!secret_bad) {
        printf "PASS  ci.yml needs no repository secret\n"
      }
      if (!continue_bad) {
        printf "PASS  no job continues on error\n"
      }
      if (!trigger_bad) {
        printf "PASS  the workflow uses only reviewed triggers and never pull_request_target\n"
      }
      if (step_name_bad) {
        note("an artifact upload name or overwrite flag is outside the reviewed allowlist")
      }
      if (uploads == 0) {
        note("no artifact upload step was found")
      } else if (uploads_retained == uploads && uploads_missing == 0 && !retention_bad) {
        printf "PASS  every uploaded artifact has a retention limit\n"
      } else {
        note(sprintf("%d uploads and %d retention limits; each upload needs a limit", uploads, uploads_retained))
      }
    }
  ' "$1"
}

# Run one scan function and relay its PASS and FAIL lines to the audit counters.
run_workflow_scan() {
  if ! report=$("$1" "$workflow"); then
    fail "$2 failed to run"
    return
  fi
  # A scan that reports nothing proved nothing. Count the result lines and
  # fail closed when there are none.
  scan_lines=0
  while IFS= read -r line; do
    case "$line" in
      "PASS  "*) pass "${line#PASS  }"; scan_lines=$((scan_lines + 1)) ;;
      "FAIL  "*) fail "${line#FAIL  }"; scan_lines=$((scan_lines + 1)) ;;
    esac
  done <<EOF
$report
EOF
  if [ "$scan_lines" -eq 0 ]; then
    fail "$2 reported no result"
  fi
}

# Read the one version key of the [package] table in a Cargo manifest. A
# version in [package.metadata], a duplicate key, a quoted key this reader
# cannot review, or another table fails closed. The caller reports the failure.
manifest_version() {
  awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function strip_comment(s,   i, n, c, q, out) {
      out = ""; q = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q == "") {
          if (c == "#") break
          if (c == "\"" || c == "\047") { q = c; out = out c; continue }
          out = out c
          continue
        }
        out = out c
        if (q == "\"" && c == "\\") {
          if (i < n) { i++; out = out substr(s, i, 1) }
          continue
        }
        if (c == q) q = ""
      }
      return out
    }
    function string_value(v,   q, n, i, c, out, rest) {
      v = trim(v); q = substr(v, 1, 1)
      if (q != "\"" && q != "\047") return ""
      out = ""; n = length(v)
      for (i = 2; i <= n; i++) {
        c = substr(v, i, 1)
        if (q == "\"" && c == "\\") return ""
        if (c == q) {
          rest = trim(substr(v, i + 1))
          if (rest != "") return ""
          return out
        }
        out = out c
      }
      return ""
    }
    function bare_key(k,   q, n) {
      k = trim(k)
      if (k == "") return ""
      q = substr(k, 1, 1)
      if (q == "\"" || q == "\047") {
        n = length(k)
        if (n < 2 || substr(k, n, 1) != q) return ""
        return substr(k, 2, n - 2)
      }
      return k
    }
    BEGIN { section = ""; pkg = 0; count = 0; value = ""; bad = 0 }
    {
      line = trim(strip_comment($0))
      if (line == "") next
      # A multi-line TOML string can hold a line that looks like a package
      # key. This reader reviews one-line values only and fails closed instead
      # of reading text from inside a string.
      if (index(line, "\"\"\"") > 0 || index(line, "\047\047\047") > 0) { bad = 1; next }
      if (substr(line, 1, 1) == "[") {
        if (substr(line, 1, 2) == "[[") { section = ""; next }
        if (substr(line, length(line), 1) != "]") { bad = 1; next }
        section = trim(substr(line, 2, length(line) - 2))
        if (section == "package") pkg++
        next
      }
      if (section != "package") next
      p = index(line, "=")
      if (p == 0) next
      key = bare_key(substr(line, 1, p - 1))
      if (key != "version") next
      count++
      v = string_value(substr(line, p + 1))
      if (v == "") { bad = 1; next }
      value = v
    }
    END {
      if (bad || pkg != 1 || count != 1 || value == "") exit 1
      print value
    }
  ' "$1"
}

# Read the version of the root package entry in a Cargo lockfile. The root
# entry is the one with no source key. A dependency with the same package name
# is not the root. A missing, duplicated, or ambiguous root entry fails closed.
lock_version() {
  awk -v want="$2" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function strip_comment(s,   i, n, c, q, out) {
      out = ""; q = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q == "") {
          if (c == "#") break
          if (c == "\"" || c == "\047") { q = c; out = out c; continue }
          out = out c
          continue
        }
        out = out c
        if (q == "\"" && c == "\\") {
          if (i < n) { i++; out = out substr(s, i, 1) }
          continue
        }
        if (c == q) q = ""
      }
      return out
    }
    function string_value(v,   q, n, i, c, out, rest) {
      v = trim(v); q = substr(v, 1, 1)
      if (q != "\"" && q != "\047") return ""
      out = ""; n = length(v)
      for (i = 2; i <= n; i++) {
        c = substr(v, i, 1)
        if (q == "\"" && c == "\\") return ""
        if (c == q) {
          rest = trim(substr(v, i + 1))
          if (rest != "") return ""
          return out
        }
        out = out c
      }
      return ""
    }
    function bare_key(k,   q, n) {
      k = trim(k)
      if (k == "") return ""
      q = substr(k, 1, 1)
      if (q == "\"" || q == "\047") {
        n = length(k)
        if (n < 2 || substr(k, n, 1) != q) return ""
        return substr(k, 2, n - 2)
      }
      return k
    }
    function finish(   ) {
      if (block && name == want) {
        if (!has_source) {
          roots++
          if (!has_version || version == "") bad = 1
          root_value = version
        }
      }
      block = 0; name = ""; version = ""
      has_name = 0; has_version = 0; has_source = 0
    }
    BEGIN { block = 0; roots = 0; root_value = ""; bad = 0 }
    {
      line = trim(strip_comment($0))
      if (line == "") next
      # A multi-line string in a lockfile is outside the reviewed subset and
      # could hold a fake package key. Fail closed.
      if (index(line, "\"\"\"") > 0 || index(line, "\047\047\047") > 0) { bad = 1; next }
      if (substr(line, 1, 2) == "[[") {
        finish()
        if (line == "[[package]]") block = 1
        next
      }
      if (substr(line, 1, 1) == "[") { finish(); next }
      if (!block) next
      p = index(line, "=")
      if (p == 0) next
      key = bare_key(substr(line, 1, p - 1))
      if (key == "name") {
        if (has_name) bad = 1
        has_name = 1
        name = string_value(substr(line, p + 1))
        if (name == "") bad = 1
      } else if (key == "version") {
        if (has_version) bad = 1
        has_version = 1
        version = string_value(substr(line, p + 1))
        if (version == "") bad = 1
      } else if (key == "source") {
        if (has_source) bad = 1
        has_source = 1
      }
    }
    END {
      finish()
      if (bad || roots != 1 || root_value == "") exit 1
      print root_value
    }
  ' "$1"
}

# Read the root "version" string of a JSON object. A nested version, a version
# in a string value, a comment, a duplicate root key, or malformed JSON fails
# closed. The caller reports the failure.
json_version() {
  awk '
    function trim(s) { sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
    function hex_digit(c,   n) {
      n = index("0123456789abcdef", tolower(c))
      return n - 1
    }
    function skip_ws(   c) {
      while (POS <= LEN) {
        c = substr(TEXT, POS, 1)
        if (c == " " || c == "\t" || c == "\n" || c == "\r") POS++
        else break
      }
    }
    function parse_string(   c, e, out, i, code) {
      if (substr(TEXT, POS, 1) != "\"") return 0
      POS++
      out = ""
      ESC = 0
      while (POS <= LEN) {
        c = substr(TEXT, POS, 1)
        if (c == "\"") {
          POS++
          STR = out
          return 1
        }
        if (c == "\\") {
          ESC = 1
          POS++
          e = substr(TEXT, POS, 1)
          if (e == "\"" || e == "\\" || e == "/") out = out e
          else if (e == "b") out = out sprintf("%c", 8)
          else if (e == "f") out = out sprintf("%c", 12)
          else if (e == "n") out = out "\n"
          else if (e == "r") out = out "\r"
          else if (e == "t") out = out "\t"
          else if (e == "u") {
            if (POS + 4 > LEN) return 0
            code = 0
            for (i = 1; i <= 4; i++) {
              h = hex_digit(substr(TEXT, POS + i, 1))
              if (h < 0) return 0
              code = code * 16 + h
            }
            out = out "?"
            POS += 4
          } else {
            return 0
          }
          POS++
          continue
        }
        if (c ~ /[\001-\037]/) return 0
        out = out c
        POS++
      }
      return 0
    }
    function parse_value(   c, start, token) {
      skip_ws()
      if (POS > LEN) return 0
      c = substr(TEXT, POS, 1)
      if (c == "{") { depth++; if (!parse_object()) return 0; depth--; return 1 }
      if (c == "[") return parse_array()
      if (c == "\"") return parse_string()
      start = POS
      while (POS <= LEN) {
        c = substr(TEXT, POS, 1)
        if (c == " " || c == "\t" || c == "\n" || c == "\r" || c == "," || c == "]" || c == "}") break
        POS++
      }
      token = substr(TEXT, start, POS - start)
      if (token == "true" || token == "false" || token == "null") return 1
      if (token ~ /^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?$/) return 1
      return 0
    }
    function parse_array(   c) {
      POS++
      skip_ws()
      if (substr(TEXT, POS, 1) == "]") { POS++; return 1 }
      while (1) {
        if (!parse_value()) return 0
        skip_ws()
        c = substr(TEXT, POS, 1)
        if (c == ",") { POS++; skip_ws(); continue }
        if (c == "]") { POS++; return 1 }
        return 0
      }
    }
    function parse_object(   c, key, key_esc) {
      POS++
      skip_ws()
      if (substr(TEXT, POS, 1) == "}") { POS++; return 1 }
      while (1) {
        skip_ws()
        if (!parse_string()) return 0
        key = STR
        key_esc = ESC
        # A root key that needs a YAML or JSON escape can spell a second
        # "version" key without matching this reader. Reject it instead.
        if (depth == 1 && key_esc) return 0
        if (depth == 1) {
          if (key in root_key) return 0
          root_key[key] = 1
        }
        skip_ws()
        if (substr(TEXT, POS, 1) != ":") return 0
        POS++
        skip_ws()
        if (depth == 1 && key == "version") {
          if (!parse_string()) return 0
          if (ESC || STR == "") return 0
          version_count++
          version_value = STR
        } else {
          if (!parse_value()) return 0
        }
        skip_ws()
        c = substr(TEXT, POS, 1)
        if (c == ",") { POS++; continue }
        if (c == "}") { POS++; return 1 }
        return 0
      }
    }
    BEGIN {
      TEXT = ""; POS = 1; LEN = 0; depth = 0
      version_count = 0; version_value = ""
      text = ""
    }
    { TEXT = TEXT $0 "\n" }
    END {
      LEN = length(TEXT)
      skip_ws()
      if (substr(TEXT, POS, 1) != "{") exit 1
      depth = 1
      if (!parse_object()) exit 1
      depth = 0
      skip_ws()
      if (POS <= LEN) exit 1
      if (version_count != 1 || version_value == "") exit 1
      print version_value
    }
  ' "$1"
}

# Remove OpenStep comments from an Xcode project file. A comment outside a
# quoted string becomes one space, so two tokens cannot merge. An unterminated
# comment, a nested comment, or a quoted string that crosses a line fails
# closed. The caller reports the failure.
pbxproj_clean() {
  awk '
    BEGIN { state = 0; bad = 0 }
    {
      line = $0; out = ""; n = length(line); i = 1
      while (i <= n) {
        c = substr(line, i, 1)
        if (state == 1) {
          if (c == "*" && substr(line, i + 1, 1) == "/") { state = 0; i += 2; continue }
          if (c == "/" && substr(line, i + 1, 1) == "*") bad = 1
          i++
          continue
        }
        if (state == 2) { i = n + 1; continue }
        if (state == 3) {
          out = out c
          if (c == "\\") {
            if (i < n) { i++; out = out substr(line, i, 1) } else bad = 1
            i++
            continue
          }
          if (c == "\"") state = 0
          i++
          continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { state = 1; out = out " "; i += 2; continue }
        if (c == "/" && substr(line, i + 1, 1) == "/") { state = 2; out = out " "; i = n + 1; continue }
        if (c == "\"") { state = 3; out = out c; i++; continue }
        out = out c
        i++
      }
      if (state == 3) { bad = 1; state = 0 }
      if (state == 2) state = 0
      printf "%s\n", out
    }
    END { if (state == 1 || bad) exit 1 }
  ' "$1"
}

# Read the Debug and Release configurations of the macOS app target. The
# reader strips comments, accepts any whitespace or line layout in the reviewed
# OpenStep subset, and requires exactly one marketing version in each app
# configuration. A duplicate key, an unsupported construct, or a configuration
# that cannot be attributed fails closed.
pbxproj_target_versions_complete() {
  cleaned=$(pbxproj_clean "$1") || return 1
  printf '%s\n' "$cleaned" | awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function is_space(c) { return c == " " || c == "\t" || c == "\n" }
    function skip_ws(s, i,   n) {
      n = length(s)
      while (i <= n && is_space(substr(s, i, 1))) i++
      return i
    }
    function skip_string(s, i,   n, c) {
      n = length(s); i++
      while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\") { i += 2; continue }
        if (c == "\"") return i + 1
        if (c == "\n") return 0
        i++
      }
      return 0
    }
    function skip_array(s, i,   n, level, c, e) {
      n = length(s); level = 0
      while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\"") {
          e = skip_string(s, i)
          if (e == 0) return 0
          i = e
          continue
        }
        if (c == "(") level++
        else if (c == ")") {
          level--
          if (level == 0) return i + 1
        } else if (c == "{") return 0
        i++
      }
      return 0
    }
    function reset_depth(d) {
      gen[d]++
      isa[d] = ""; has_isa[d] = 0
      name[d] = ""; has_name[d] = 0
      bundle[d] = ""; has_bundle[d] = 0
      mv_count[d] = 0; mv_value[d] = ""
      bs_bundle[d] = ""; has_bs_bundle[d] = 0
      bs_mv_count[d] = 0; bs_mv_value[d] = ""
      key_at[d] = ""
    }
    # A conditional version or Info.plist setting carries a [condition]
    # suffix. The reader does not model build-setting conditions, so it cannot
    # tell which value wins. A direct INFOPLIST_KEY_CFBundleShortVersionString
    # setting can replace the generated bundle version without appearing as
    # MARKETING_VERSION. Reject these instead of reporting a version the app
    # may not carry. An unrelated conditional setting is still reviewed.
    function setting_is_unreviewed(k) {
      if (k ~ /^MARKETING_VERSION\[/) return 1
      if (k == "INFOPLIST_KEY_CFBundleShortVersionString") return 1
      if (k ~ /^INFOPLIST_KEY_CFBundleShortVersionString\[/) return 1
      if (k ~ /^INFOPLIST_KEY_/ && index(k, "[") > 0) return 1
      if (k ~ /^PRODUCT_BUNDLE_IDENTIFIER\[/) return 1
      if (k ~ /^(GENERATE_INFOPLIST_FILE|INFOPLIST_FILE|CURRENT_PROJECT_VERSION)\[/) return 1
      return 0
    }
    function assign(d, k, v,   ck) {
      if (d < 1) { bad = 1; return }
      # A key escape can spell a conditional suffix without matching a text
      # check. This reader does not decode escapes, so reject the spelling.
      if (index(k, "\\") > 0) { bad = 1; return }
      if (setting_is_unreviewed(k)) { bad = 1; return }
      ck = d SUBSEP gen[d] SUBSEP k
      if (ck in scalar_seen) { bad = 1; return }
      scalar_seen[ck] = 1
      if (k == "isa") { isa[d] = v; has_isa[d] = 1 }
      else if (k == "name") { name[d] = v; has_name[d] = 1 }
      else if (k == "PRODUCT_BUNDLE_IDENTIFIER") { bundle[d] = v; has_bundle[d] = 1 }
      else if (k == "MARKETING_VERSION") { mv_count[d]++; mv_value[d] = v }
    }
    function push_dict(parent, k,   ck) {
      if (k == "") return
      ck = parent SUBSEP gen[parent] SUBSEP k
      if (ck in child_seen) bad = 1
      child_seen[ck] = 1
    }
    function close_dict(d,   p, app) {
      if (has_isa[d] && isa[d] == "XCBuildConfiguration") {
        if (!has_name[d]) bad = 1
        # PRODUCT_BUNDLE_IDENTIFIER belongs in buildSettings. A value at the
        # configuration level is not where Xcode reads the app identity, so
        # this reader cannot use it to select the app target. Reject the
        # ambiguous spelling instead of guessing which target the config is.
        if (has_bundle[d]) bad = 1
        app = (has_bs_bundle[d] && bs_bundle[d] == "dev.hotspotshade.mac")
        if (app) {
          configs++
          # Only a MARKETING_VERSION inside the app configuration buildSettings
          # is the value Xcode applies. A version at the configuration level is
          # a decoy that Xcode does not read as a build setting.
          if (mv_count[d] != 0) bad = 1
          if (bs_mv_count[d] != 1 || bs_mv_value[d] == "") bad = 1
          if (name[d] == "Debug") { debug++; debug_mv = bs_mv_value[d] }
          else if (name[d] == "Release") { release++; release_mv = bs_mv_value[d] }
          else bad = 1
        }
      }
      if (d > 0 && key_at[d] == "buildSettings") {
        p = d - 1
        has_bs_bundle[p] = has_bundle[d]
        bs_bundle[p] = bundle[d]
        bs_mv_count[p] = mv_count[d]
        bs_mv_value[p] = mv_value[d]
      }
    }
    # Consume a scalar, array, or dictionary value starting at j. VAL_KIND and
    # VAL hold a scalar. A dictionary is left at its opening brace so the main
    # loop can push it with its key.
    function read_value(s, j,   n, c, e, start) {
      n = length(s); j = skip_ws(s, j)
      c = substr(s, j, 1)
      if (c == "{") { VAL_KIND = "dict"; return j }
      if (c == "(") {
        e = skip_array(s, j)
        if (e == 0) { VAL_KIND = "bad"; return 0 }
        VAL_KIND = "array"; j = e
      } else if (c == "\"") {
        e = skip_string(s, j)
        if (e == 0) { VAL_KIND = "bad"; return 0 }
        VAL = substr(s, j + 1, e - j - 2)
        VAL_KIND = "scalar"; j = e
      } else {
        start = j
        while (j <= n) {
          c = substr(s, j, 1)
          if (c == ";") break
          if (c == "}" || c == "\n") { VAL_KIND = "bad"; return 0 }
          j++
        }
        if (j > n) { VAL_KIND = "bad"; return 0 }
        VAL = trim(substr(s, start, j - start))
        VAL_KIND = "scalar"
      }
      j = skip_ws(s, j)
      if (substr(s, j, 1) != ";") { VAL_KIND = "bad"; return 0 }
      return j + 1
    }
    BEGIN { pending_key = ""; bad = 0; configs = 0; debug = 0; release = 0
            debug_mv = ""; release_mv = "" }
    { text = text $0 "\n" }
    END {
      n = length(text); i = 1; depth = 0
      reset_depth(0)
      while (i <= n) {
        i = skip_ws(text, i)
        if (i > n) break
        c = substr(text, i, 1)
        if (c == "}") {
          if (depth <= 0) { bad = 1; break }
          close_dict(depth)
          depth--
          if (depth >= 1) {
            j = skip_ws(text, i + 1)
            if (substr(text, j, 1) != ";") { bad = 1; break }
            i = j + 1
          } else {
            i++
          }
          continue
        }
        if (c == "{") {
          push_dict(depth, pending_key)
          depth++
          reset_depth(depth)
          key_at[depth] = pending_key
          pending_key = ""
          i++
          continue
        }
        if (c == ";" || c == "," || c == "=") { i++; continue }
        if (c == "\"") {
          e = skip_string(text, i)
          if (e == 0) { bad = 1; break }
          key = substr(text, i + 1, e - i - 2)
          i = e
        } else {
          start = i
          while (i <= n) {
            c = substr(text, i, 1)
            if (is_space(c) || c == "=" || c == ";" || c == "{" || c == "}" || c == "(" || c == ")" || c == ",") break
            i++
          }
          if (i == start) { i++; continue }
          key = substr(text, start, i - start)
        }
        j = skip_ws(text, i)
        if (substr(text, j, 1) != "=") { i = (j > i ? j : i + 1); continue }
        j = skip_ws(text, j + 1)
        e = read_value(text, j)
        if (VAL_KIND == "bad" || e == 0) { bad = 1; break }
        if (VAL_KIND == "dict") {
          pending_key = key
          i = e
        } else {
          assign(depth, key, VAL)
          i = e
        }
      }
      if (depth != 0) bad = 1
      if (bad || configs != 2 || debug != 1 || release != 1) exit 1
      if (debug_mv == "" || release_mv == "" || debug_mv != release_mv) exit 1
      print debug_mv
      exit 0
    }
  '
}

# Read the one <string> value of a plist key. The reader walks the XML tree and
# accepts only the key as a direct child of the root <plist> dict. XML comments
# are removed first, a comment cannot supply a key or a value, a nested key is
# not the root key, and a duplicate root key fails closed.
plist_version() {
  awk -v key="$2" '
    function trim(s) { sub(/^[ \t\n\r]+/, "", s); sub(/[ \t\n\r]+$/, "", s); return s }
    function is_space(c) { return c == " " || c == "\t" || c == "\n" || c == "\r" }
    function skip_ws(i) {
      while (i <= LEN && is_space(substr(TEXT, i, 1))) i++
      return i
    }
    # Read one tag at i. TAG_NAME holds the element name. A closing tag sets
    # TAG_CLOSE, a self-closing tag sets TAG_SELF, and TAG_END points at >.
    function read_tag(i,   j, c, q, k) {
      TAG_NAME = ""; TAG_CLOSE = 0; TAG_SELF = 0; TAG_END = 0
      if (substr(TEXT, i, 1) != "<") return 0
      if (substr(TEXT, i, 2) == "</") {
        j = i + 2
        while (j <= LEN && !is_space(substr(TEXT, j, 1)) && substr(TEXT, j, 1) != ">") j++
        TAG_NAME = substr(TEXT, i + 2, j - i - 2)
        j = skip_ws(j)
        if (TAG_NAME == "" || substr(TEXT, j, 1) != ">") return 0
        TAG_CLOSE = 1
        TAG_END = j
        return 1
      }
      j = i + 1
      while (j <= LEN && !is_space(substr(TEXT, j, 1)) &&
             substr(TEXT, j, 1) != ">" && substr(TEXT, j, 1) != "/") j++
      TAG_NAME = substr(TEXT, i + 1, j - i - 1)
      q = ""
      while (j <= LEN) {
        c = substr(TEXT, j, 1)
        if (q != "") {
          if (c == q) q = ""
          j++
          continue
        }
        if (c == "\"" || c == "\047") { q = c; j++; continue }
        if (c == ">") break
        j++
      }
      if (TAG_NAME == "" || j > LEN) return 0
      k = j - 1
      while (k > i && is_space(substr(TEXT, k, 1))) k--
      if (substr(TEXT, k, 1) == "/") TAG_SELF = 1
      TAG_END = j
      return 1
    }
    function finish_key(   v) {
      v = trim(CAPTEXT)
      if (v == "" || have_pending) { badflag = 1; return 0 }
      pending = v
      have_pending = 1
      expect_key = 0
      CAPTEXT = ""
      capture = ""
      return 1
    }
    function finish_value(   v) {
      v = trim(CAPTEXT)
      if (v == "" || !have_pending) { badflag = 1; return 0 }
      if (pending == key) {
        count++
        value = v
      }
      pending = ""
      have_pending = 0
      expect_key = 1
      CAPTEXT = ""
      capture = ""
      return 1
    }
    BEGIN { TEXT = ""; badflag = 0 }
    { TEXT = TEXT $0 "\n" }
    END {
      out = ""
      while ((p = index(TEXT, "<!--")) > 0) {
        out = out substr(TEXT, 1, p - 1)
        rest = substr(TEXT, p + 4)
        q = index(rest, "-->")
        if (q == 0) { badflag = 1; break }
        TEXT = substr(rest, q + 3)
      }
      if (badflag) exit 1
      TEXT = out TEXT
      LEN = length(TEXT)
      depth = 0
      stack[0] = ""
      root_count = 0
      dict_count = 0
      top_dict = -1
      pending = ""
      have_pending = 0
      expect_key = 0
      capture = ""
      cap_depth = -1
      CAPTEXT = ""
      count = 0
      value = ""
      i = 1
      while (i <= LEN) {
        if (substr(TEXT, i, 1) != "<") {
          j = index(substr(TEXT, i), "<")
          if (j == 0) j = LEN + 1
          else j = i + j - 1
          chunk = substr(TEXT, i, j - i)
          if (capture != "" && depth == cap_depth) {
            if (index(chunk, "&") > 0) { badflag = 1; break }
            CAPTEXT = CAPTEXT chunk
          } else if ((top_dict < 0 || depth <= top_dict) && chunk ~ /[^ \t\r\n]/) {
            badflag = 1
            break
          }
          i = j
          continue
        }
        if (substr(TEXT, i, 2) == "<?") {
          e = index(substr(TEXT, i + 2), "?>")
          if (e == 0) { badflag = 1; break }
          i = i + 2 + e + 1
          continue
        }
        if (substr(TEXT, i, 9) == "<![CDATA[") { badflag = 1; break }
        if (substr(TEXT, i, 2) == "<!") {
          j = i + 2
          q = ""
          bracket = 0
          while (j <= LEN) {
            c = substr(TEXT, j, 1)
            if (q != "") {
              if (c == q) q = ""
              j++
              continue
            }
            if (c == "\"" || c == "\047") { q = c; j++; continue }
            if (c == "[") { bracket++; j++; continue }
            if (c == "]") { if (bracket > 0) bracket--; j++; continue }
            if (c == ">" && bracket == 0) break
            j++
          }
          if (j > LEN) { badflag = 1; break }
          i = j + 1
          continue
        }
        if (!read_tag(i)) { badflag = 1; break }
        if (capture != "" && !(TAG_CLOSE && TAG_NAME == stack[depth])) {
          badflag = 1
          break
        }
        if (TAG_CLOSE) {
          if (depth <= 0 || stack[depth] != TAG_NAME) { badflag = 1; break }
          if (capture == "key" && depth == cap_depth) {
            if (!finish_key()) break
          } else if (capture == "value" && depth == cap_depth) {
            if (!finish_value()) break
          }
          if (depth == top_dict && have_pending) { badflag = 1; break }
          depth--
          i = TAG_END + 1
          continue
        }
        if (capture != "") { badflag = 1; break }
        name = TAG_NAME
        if (depth == 0) {
          if (name != "plist") { badflag = 1; break }
          root_count++
          if (root_count > 1) { badflag = 1; break }
        } else if (depth == 1 && stack[1] == "plist") {
          if (name != "dict") { badflag = 1; break }
          dict_count++
          if (dict_count > 1) { badflag = 1; break }
          top_dict = 2
          expect_key = 1
        } else if (depth == top_dict) {
          if (name == "key") {
            if (!expect_key || have_pending || TAG_SELF) { badflag = 1; break }
            capture = "key"
            cap_depth = depth + 1
            CAPTEXT = ""
          } else {
            if (!have_pending) { badflag = 1; break }
            if (pending == key) {
              if (name != "string" || TAG_SELF) { badflag = 1; break }
              capture = "value"
              cap_depth = depth + 1
              CAPTEXT = ""
            } else {
              pending = ""
              have_pending = 0
              expect_key = 1
            }
          }
        }
        if (!TAG_SELF) {
          depth++
          stack[depth] = name
        } else if (name == "dict" && depth == 1 && stack[1] == "plist") {
          badflag = 1
          break
        }
        i = TAG_END + 1
      }
      if (depth != 0 || root_count != 1 || dict_count != 1 || top_dict != 2) badflag = 1
      if (capture != "" || have_pending || !expect_key) badflag = 1
      if (badflag || count != 1 || value == "") exit 1
      print value
    }
  ' "$1"
}

# Read the Android versionName. Only one assignment may appear directly in the
# `defaultConfig` block of the top-level `android` block. A comment, a string,
# a nested build type, a duplicate assignment, or an unsupported spelling fails
# closed instead of selecting a decoy. The caller reports the failure.
gradle_version() {
  awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function skip_ws(i) {
      while (i <= LEN) {
        c = substr(TEXT, i, 1)
        if (c == " " || c == "\t" || c == "\n" || c == "\r") i++
        else break
      }
      return i
    }
    function read_string(i,   q, out, c) {
      q = substr(TEXT, i, 1)
      i++
      out = ""
      STR_ESC = 0
      while (i <= LEN) {
        c = substr(TEXT, i, 1)
        if (c == "\\") { STR_ESC = 1; i += 2; continue }
        if (c == q) { STR = out; return i + 1 }
        if (c == "\n") return 0
        out = out c
        i++
      }
      return 0
    }
    BEGIN { TEXT = ""; comment = 0; bad = 0 }
    {
      line = $0
      out = ""
      i = 1
      n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)
        if (comment > 0) {
          if (c == "/" && substr(line, i + 1, 1) == "*") { comment++; i += 2; continue }
          if (c == "*" && substr(line, i + 1, 1) == "/") { comment--; i += 2; continue }
          i++
          continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { comment = 1; i += 2; continue }
        if (c == "/" && substr(line, i + 1, 1) == "/") break
        if (c == "\"" || c == "\047") {
          q = c
          out = out c
          i++
          while (i <= n) {
            c = substr(line, i, 1)
            out = out c
            if (c == "\\") {
              if (i < n) { i++; out = out substr(line, i, 1) }
              else bad = 1
              i++
              continue
            }
            i++
            if (c == q) break
          }
          if (c != q) bad = 1
          continue
        }
        out = out c
        i++
      }
      TEXT = TEXT out "\n"
    }
    END {
      if (comment) bad = 1
      LEN = length(TEXT)
      pos = 1
      depth = 0
      count = 0
      value = ""
      last = ""
      while (pos <= LEN) {
        pos = skip_ws(pos)
        if (pos > LEN) break
        c = substr(TEXT, pos, 1)
        if (c == "\"" || c == "\047") {
          e = read_string(pos)
          if (e == 0) { bad = 1; break }
          pos = e
          last = ""
          continue
        }
        if (c ~ /[A-Za-z_]/) {
          start = pos
          while (pos <= LEN && substr(TEXT, pos, 1) ~ /[A-Za-z0-9_]/) pos++
          ident = substr(TEXT, start, pos - start)
          # A versionNameSuffix changes the built version, and a flavor can
          # override versionName or add its own suffix. The audit reads one
          # defaultConfig string, so a suffix, a flavor dimension, or a
          # product flavor is outside the reviewed subset. Fail closed instead
          # of reporting a base version that the APK will not carry.
          if (last != "val" && last != "var") {
            if (ident == "versionNameSuffix") {
              bad = 1
              break
            }
            # The Android Components DSL can set a variant versionName after
            # defaultConfig. The audit does not evaluate that DSL, so reject
            # the block instead of reporting a value another block replaces.
            if (ident == "androidComponents") {
              bad = 1
              break
            }
            if ((ident == "productFlavors" || ident == "flavorDimensions") &&
                depth >= 1 && stack[1] == "android") {
              bad = 1
              break
            }
            # A dotted versionName is a reference such as
            # defaultConfig.versionName or variant.versionName. It can override
            # the reviewed defaultConfig assignment, so fail closed. A call
            # such as versionName.set(...) is rejected the same way.
            if (ident == "versionName") {
              if (substr(TEXT, start - 1, 1) == "." ||
                  substr(TEXT, skip_ws(pos), 1) == ".") {
                bad = 1
                break
              }
            }
          }
          if (ident == "versionName" && last != "val" && last != "var" &&
              substr(TEXT, start - 1, 1) != ".") {
            q = skip_ws(pos)
            if (substr(TEXT, q, 1) == "=") {
              q = skip_ws(q + 1)
              if (substr(TEXT, q, 1) != "\"") {
                bad = 1
                break
              }
              e = read_string(q)
              if (e == 0 || STR == "" || STR_ESC) { bad = 1; break }
              # A single string literal ends the assignment. A concatenation,
              # a method call, or a conditional expression changes the built
              # version, so reject that spelling instead of reading a prefix.
              r = e
              while (r <= LEN && substr(TEXT, r, 1) ~ /[ \t\r]/) r++
              if (r <= LEN) {
                rc = substr(TEXT, r, 1)
                if (rc != ";" && rc != "}" && rc != "\n") { bad = 1; break }
                if (rc == "\n") {
                  s = r + 1
                  while (s <= LEN && substr(TEXT, s, 1) ~ /[ \t\r\n]/) s++
                  sc = substr(TEXT, s, 1)
                  if (sc == "+" || sc == "." || sc == "?" || sc == ":" || sc == "(") {
                    bad = 1
                    break
                  }
                }
              }
              # A versionName in a nested block is a decoy. It is ignored only
              # when a real defaultConfig assignment exists; with no real one
              # the count stays zero and the caller fails closed.
              if (depth == 2 && stack[1] == "android" && stack[2] == "defaultConfig") {
                count++
                value = STR
              }
              pos = e
              last = ""
              continue
            }
          }
          last = ident
          continue
        }
        if (c == "{") {
          depth++
          if (last == "") { bad = 1; break }
          stack[depth] = last
          last = ""
          pos++
          continue
        }
        if (c == "}") {
          if (depth <= 0) { bad = 1; break }
          depth--
          last = ""
          pos++
          continue
        }
        if (c == "(" || c == ")" || c == "=" || c == ";" || c == ",") {
          last = ""
          pos++
          continue
        }
        pos++
      }
      if (bad || depth != 0 || count != 1 || value == "") exit 1
      print value
    }
  ' "$1"
}

# Read the Version attribute of the Package/Identity element in an appx
# manifest. Comments are removed first. An Identity nested under another
# element, a Version on another element, a duplicate Identity, a duplicate
# Version attribute, an unquoted value, or a malformed tag fails closed.
appx_version() {
  awk '
    function trim(s) { sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
    BEGIN { text = ""; bad = 0 }
    { text = text $0 "\n" }
    END {
      out = ""
      while ((p = index(text, "<!--")) > 0) {
        out = out substr(text, 1, p - 1)
        rest = substr(text, p + 4)
        q = index(rest, "-->")
        if (q == 0) { bad = 1; break }
        text = substr(rest, q + 3)
      }
      if (bad) exit 1
      text = out text
      n = length(text)
      i = 1
      depth = 0
      parent = ""
      package_count = 0
      identity_count = 0
      identity_version = ""
      while (i <= n) {
        c = substr(text, i, 1)
        if (c != "<") { i++; continue }
        if (substr(text, i, 2) == "</") {
          e = index(substr(text, i + 2), ">")
          if (e == 0) { bad = 1; break }
          name = trim(substr(text, i + 2, e - 1))
          if (name == "" || depth <= 0 || stack[depth] != name) { bad = 1; break }
          depth--
          parent = (depth > 0) ? stack[depth] : ""
          i = i + 2 + e
          continue
        }
        if (substr(text, i, 2) == "<?") {
          e = index(substr(text, i + 2), "?>")
          if (e == 0) { bad = 1; break }
          i = i + 2 + e + 1
          continue
        }
        if (substr(text, i, 4) == "<!--") { bad = 1; break }
        j = i + 1
        quote = ""
        e = 0
        while (j <= n) {
          c = substr(text, j, 1)
          if (quote != "") {
            if (c == quote) quote = ""
            j++
            continue
          }
          if (c == "\"" || c == "\047") { quote = c; j++; continue }
          if (c == ">") { e = j; break }
          j++
        }
        if (e == 0) { bad = 1; break }
        tag = substr(text, i + 1, e - i - 1)
        selfclose = 0
        if (substr(tag, length(tag), 1) == "/") {
          selfclose = 1
          tag = substr(tag, 1, length(tag) - 1)
        }
        p = 1
        while (p <= length(tag) && substr(tag, p, 1) ~ /[ \t\r\n]/) p++
        start = p
        while (p <= length(tag) && substr(tag, p, 1) !~ /[ \t\r\n\/>]/) p++
        name = substr(tag, start, p - start)
        if (name == "") { bad = 1; break }
        if (depth == 0) {
          if (name != "Package") { bad = 1; break }
          package_count++
          if (package_count > 1) { bad = 1; break }
        }
        attr_count = 0
        attr_version_count = 0
        attr_version_value = ""
        while (p <= length(tag)) {
          while (p <= length(tag) && substr(tag, p, 1) ~ /[ \t\r\n]/) p++
          if (p > length(tag)) break
          if (substr(tag, p, 1) == "/") { p++; continue }
          astart = p
          while (p <= length(tag) && substr(tag, p, 1) !~ /[ \t\r\n=]/) p++
          aname = substr(tag, astart, p - astart)
          if (aname == "") { bad = 1; break }
          while (p <= length(tag) && substr(tag, p, 1) ~ /[ \t\r\n]/) p++
          if (substr(tag, p, 1) != "=") { bad = 1; break }
          p++
          while (p <= length(tag) && substr(tag, p, 1) ~ /[ \t\r\n]/) p++
          q = substr(tag, p, 1)
          if (q != "\"" && q != "\047") { bad = 1; break }
          p++
          vstart = p
          while (p <= length(tag) && substr(tag, p, 1) != q) p++
          if (p > length(tag)) { bad = 1; break }
          aval = substr(tag, vstart, p - vstart)
          p++
          attr_count++
          if (aname == "Version") {
            attr_version_count++
            attr_version_value = aval
          }
        }
        if (bad) break
        if (name == "Identity") {
          if (parent != "Package") { bad = 1; break }
          identity_count++
          if (attr_version_count != 1) { bad = 1; break }
          identity_version = attr_version_value
        }
        if (!selfclose) {
          depth++
          stack[depth] = name
          parent = name
        } else {
          parent = (depth > 0) ? stack[depth] : ""
        }
        i = e + 1
      }
      if (depth != 0) bad = 1
      if (bad || package_count != 1 || identity_count != 1) exit 1
      if (identity_version !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) exit 1
      print identity_version
    }
  ' "$1"
}

echo "HotspotShade release audit"
echo "Tree: $root"

# ---------------------------------------------------------------------------
# Required files and lockfile agreement
# ---------------------------------------------------------------------------

required_files='
.github/workflows/ci.yml
rust/Cargo.toml
rust/Cargo.lock
desktop/Cargo.toml
desktop/Cargo.lock
linux/package.json
linux/package-lock.json
linux/helper/Cargo.toml
linux/helper/Cargo.lock
scripts/build_ipa.sh
scripts/build_mac_app.sh
scripts/artifact_versions.sh
scripts/macho_version.sh
scripts/tests/artifact_versions_test.sh
scripts/tests/macho_version_test.sh
scripts/release_manifest.sh
scripts/release_job.expected
scripts/lint_job.expected
scripts/rust_macos_job.expected
scripts/rust_windows_job.expected
scripts/rust_linux_job.expected
scripts/desktop_demo_job.expected
scripts/desktop_windows_job.expected
scripts/winui_demo_job.expected
scripts/android_demo_job.expected
scripts/ios_job.expected
scripts/macos_app_job.expected
scripts/release_audit_job.expected
scripts/verify_macos_binary_job.expected
scripts/verify_ios_ipa_job.expected
scripts/verify_macos_app_job.expected
scripts/artifact_integrity_job.expected
scripts/ci_graph_check.sh
'

missing=0
for rel in $required_files; do
  if [ ! -f "$root/$rel" ]; then
    fail "required file is missing: $rel"
    missing=1
  fi
done
[ "$missing" -eq 0 ] && pass "required files are present"

if [ ! -f "$root/rust/Cargo.toml" ]; then
  echo "FAIL  cannot read the engine version: rust/Cargo.toml is missing"
  exit 1
fi

if engine_version=$(manifest_version "$root/rust/Cargo.toml"); then
  :
else
  engine_version=""
fi
if [ -z "$engine_version" ]; then
  fail "cannot read exactly one [package] version from rust/Cargo.toml"
else
  pass "engine version: $engine_version"
  locked=$(lock_version "$root/rust/Cargo.lock" hotspotshade || true)
  if [ -z "$locked" ]; then
    fail "rust/Cargo.lock has no unambiguous root package entry named hotspotshade"
  elif [ "$locked" = "$engine_version" ]; then
    pass "rust/Cargo.lock matches the engine version"
  else
    fail "rust/Cargo.lock holds hotspotshade $locked, rust/Cargo.toml holds $engine_version"
  fi
  desktop_version=$(manifest_version "$root/desktop/Cargo.toml" 2>/dev/null || true)
  desktop_locked=$(lock_version "$root/desktop/Cargo.lock" hotspotshade-desktop 2>/dev/null || true)
  if [ -z "$desktop_locked" ]; then
    fail "desktop/Cargo.lock has no unambiguous root package entry named hotspotshade-desktop"
  elif [ "$desktop_locked" = "$desktop_version" ]; then
    pass "desktop/Cargo.lock matches the desktop version"
  else
    fail "desktop/Cargo.lock holds hotspotshade-desktop $desktop_locked, desktop/Cargo.toml holds $desktop_version"
  fi
  helper_version=$(manifest_version "$root/linux/helper/Cargo.toml" 2>/dev/null || true)
  helper_locked=$(lock_version "$root/linux/helper/Cargo.lock" hotspotshade-helper 2>/dev/null || true)
  if [ -z "$helper_locked" ]; then
    fail "linux/helper/Cargo.lock has no unambiguous root package entry named hotspotshade-helper"
  elif [ "$helper_locked" = "$helper_version" ]; then
    pass "linux/helper/Cargo.lock matches the helper version"
  else
    fail "linux/helper/Cargo.lock holds hotspotshade-helper $helper_locked, linux/helper/Cargo.toml holds $helper_version"
  fi
fi

# ---------------------------------------------------------------------------
# One release version across the artifacts that a release publishes
# ---------------------------------------------------------------------------

version_note() {
  # version_note LABEL VERSION [EXPECTED]
  if [ -z "$2" ]; then
    fail "cannot read the version: $1"
    return
  fi
  expected_version=${3:-$engine_version}
  if [ "$2" = "$expected_version" ]; then
    pass "version aligned: $1 $2"
  elif [ "$require_aligned" -eq 1 ]; then
    fail "version drift: $1 is $2, the engine is $engine_version"
  else
    warn "version drift: $1 is $2, the engine is $engine_version"
  fi
}

if [ -n "$engine_version" ]; then
  version_note "desktop/Cargo.toml" "$(manifest_version "$root/desktop/Cargo.toml" 2>/dev/null || true)"
  version_note "linux/package.json" "$(json_version "$root/linux/package.json" || true)"
  version_note "linux/package-lock.json" "$(json_version "$root/linux/package-lock.json" || true)"
  if [ -f "$root/macos/HotspotShade.xcodeproj/project.pbxproj" ]; then
    if macos_version=$(pbxproj_target_versions_complete "$root/macos/HotspotShade.xcodeproj/project.pbxproj"); then
      version_note "macOS MARKETING_VERSION" "$macos_version"
      pass "macOS Debug and Release app configurations each declare one marketing version"
    else
      fail "cannot verify both macOS app configuration versions; check the project file format and settings"
    fi
  else
    release_blocker "macOS project file is missing; its version was not checked"
  fi
  if [ -f "$root/ios/HotspotProxy/Info.plist" ]; then
    ios_version=$(plist_version "$root/ios/HotspotProxy/Info.plist" CFBundleShortVersionString || true)
    version_note "iOS CFBundleShortVersionString" "$ios_version"
  else
    release_blocker "iOS Info.plist is missing; its version was not checked"
  fi
  if [ -f "$root/android/app/build.gradle.kts" ]; then
    version_note "Android versionName" "$(gradle_version "$root/android/app/build.gradle.kts" || true)"
  else
    release_blocker "Android build file is missing; its version was not checked"
  fi
  if [ -f "$root/windows/src/HotspotShade.WinUI2/Package.appxmanifest" ]; then
    version_note "Windows appx Version" "$(appx_version "$root/windows/src/HotspotShade.WinUI2/Package.appxmanifest" || true)" "$engine_version.0"
  else
    release_blocker "WinUI appxmanifest is missing; its version was not checked"
  fi
fi

if [ -n "$tag" ]; then
  if [ "$tag" = "v$engine_version" ]; then
    pass "tag $tag matches the engine version $engine_version"
  else
    fail "tag $tag does not match the engine version $engine_version"
  fi
fi

# ---------------------------------------------------------------------------
# Repository hygiene
# ---------------------------------------------------------------------------

# A file can be force-added from a build directory that the older find scan
# pruned. Enumerate the git index when the tree is a work tree, and fall back
# to find for a plain directory such as the test fixture. Pass names through
# xargs -0 so a space cannot split one and a newline cannot hide another.
# Print the path only: never print file content, which could expose the secret.
#
# The scan fails closed. A failed git ls-files, a failed find, a failed xargs,
# a missing or unreadable tracked file, and a grep error all report a failure.
# A file the scan could not read is not evidence that the file is clean.
tracked_secret_report() {
  scan='
    root=$1
    shift
    bad=0
    for p do
      [ -n "$p" ] || continue
      case "$p" in
        "$root"/*) rel=${p#"$root"/}; full=$p ;;
        /*) rel=$p; full=$p ;;
        *) rel=$p; full=$root/$p ;;
      esac
      case "$rel" in
        .git|.git/*) continue ;;
      esac
      # A case-insensitive file system can track Key.PEM or Identity.Key, and
      # the scan must still see it. Compare the lower-case base name.
      base=${rel##*/}
      case "$base" in
        *[A-Z]*) base_lc=$(printf "%s\n" "$base" | tr "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz") || {
          printf "tracked file name could not be normalized: %s\n" "$rel"
          bad=1
          continue
        } ;;
        *) base_lc=$base ;;
      esac
      case "$base_lc" in
        *.p12|*.pfx|*.cer|*.crt|*.key|*.pem|*.p8|*.ppk|*.mobileprovision|*.provisionprofile|identity.key|wintun.dll|*.pcap|*.pcapng|*.jks|*.keystore|.env|.env.*|.netrc|.npmrc|id_rsa|id_ed25519|id_ecdsa|id_dsa)
          printf "tracked signing material or capture: %s\n" "$rel" ;;
      esac
      if [ ! -f "$full" ] || [ ! -r "$full" ]; then
        printf "tracked file is missing or unreadable: %s\n" "$rel"
        bad=1
        continue
      fi
      # Read every tracked byte, including a binary file, so a marker in a
      # blob is not hidden by the text heuristic. Print the path only.
      # LC_ALL=C keeps a byte scan of a binary file fast and avoids locale
      # decoding of arbitrary bytes. The marker set is ASCII.
      LC_ALL=C grep -aqE -- "-----BEGIN ([A-Z0-9]+[ ])*PRIVATE KEY( BLOCK)?-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk_live_[0-9A-Za-z]{20,}" "$full" >/dev/null 2>&1
      scan_status=$?
      case "$scan_status" in
        0) printf "tracked file holds a private key or access token marker: %s\n" "$rel" ;;
        1) ;;
        *) printf "tracked file could not be read for a marker scan: %s\n" "$rel"; bad=1 ;;
      esac
    done
    [ "$bad" -eq 0 ]
  '
  if ! command -v xargs >/dev/null 2>&1; then
    printf "the tracked-file scan needs xargs\n"
    return 1
  fi
  names=$(mktemp "${TMPDIR:-/tmp}/hs-tracked.XXXXXX") || {
    printf "cannot create a temporary file for the tracked-file list\n"
    return 1
  }
  use_git=no
  if command -v git >/dev/null 2>&1 &&
     [ "$(git -C "$root" rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
    use_git=yes
  elif [ -e "$root/.git" ] || [ -L "$root/.git" ]; then
    # Git metadata exists but cannot be read. Falling back to find would
    # silently skip a force-added tracked file, so fail closed.
    rm -f "$names"
    printf "cannot read the git work tree metadata\n"
    return 1
  fi
  if [ "$use_git" = yes ]; then
    if ! git -C "$root" ls-files -z -- > "$names" 2>/dev/null; then
      rm -f "$names"
      printf "cannot enumerate tracked files with git ls-files\n"
      return 1
    fi
  else
    if ! find "$root" -name .git -prune -o -type f -print0 > "$names" 2>/dev/null; then
      rm -f "$names"
      printf "cannot enumerate the tree with find\n"
      return 1
    fi
  fi
  if ! xargs -0 sh -c "$scan" sh "$root" < "$names"; then
    rm -f "$names"
    printf "the tracked-file scan could not read every tracked file\n"
    return 1
  fi
  rm -f "$names"
  return 0
}

if leaks=$(tracked_secret_report); then
  scan_status=0
else
  scan_status=$?
fi
if [ -n "$leaks" ]; then
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    fail "$path"
  done <<EOF
$leaks
EOF
fi
if [ "$scan_status" -ne 0 ]; then
  fail "the tracked-file scan could not complete; treat every tracked file as unread"
elif [ -z "$leaks" ]; then
  pass "tracked files hold no signing material, identity key, wintun.dll, capture, or token marker"
fi

if [ -f "$root/.gitignore" ]; then
  ignored=0
  for pattern in '*.ipa' '*.deb' '*.apk' 'wintun.dll' '*.pem' '*.key' '*.mobileprovision'; do
    if grep -xF "$pattern" "$root/.gitignore" >/dev/null; then
      ignored=$((ignored + 1))
    else
      fail ".gitignore does not list $pattern"
    fi
  done
  [ "$ignored" -eq 7 ] && pass ".gitignore covers build output and signing material"
else
  fail ".gitignore is missing"
fi

# ---------------------------------------------------------------------------
# Workflow policy
# ---------------------------------------------------------------------------

workflow="$root/.github/workflows/ci.yml"

if [ ! -f "$workflow" ]; then
  fail ".github/workflows/ci.yml is missing"
else
  # A second workflow file would run outside this policy. Only ci.yml is
  # reviewed. Fail on any other YAML file instead of auditing ci.yml alone.
  # A failed find is not evidence that no other workflow exists.
  if ! extra_workflows=$(find "$root/.github/workflows" ! -type d \( -iname '*.yml' -o -iname '*.yaml' \) ! -path "$workflow" -print 2>/dev/null); then
    fail "cannot enumerate the workflow directory"
    extra_workflows=""
  fi
  if [ -n "$extra_workflows" ]; then
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      fail "unreviewed workflow file: ${path#"$root"/}"
    done <<EOF
$extra_workflows
EOF
  else
    pass "ci.yml is the only workflow file"
  fi

  # Print the body of one job. Only the one plain `jobs:` mapping counts. A
  # decoy job header in a top-level block scalar is data, not a job. The
  # structure check reports every unsafe spelling; this extraction also fails
  # closed when the requested job header is not in that mapping.
  job_block() {
    awk -v job="$2" '
      BEGIN { in_jobs = 0; found = 0 }
      /^jobs:[ \t]*$/ { in_jobs = 1; next }
      !in_jobs { next }
      /^#/ { next }
      /^[^ \t]/ { exit }
      $0 == "  " job ":" { inblock = 1; found = 1; next }
      inblock && /^  [A-Za-z0-9_-]+:[ \t]*$/ { exit }
      # Comments at the job-key indentation belong between jobs. Skip them
      # instead of ending the block, so a comment inside a job cannot hide the
      # steps that follow it. A comment inside a job body is more indented and
      # stays in the block, where it must match the reviewed text.
      inblock && /^  #/ { next }
      inblock { print }
    ' "$1"
  }

  # Print one dependency of a job per line. Handles a flow list on one line
  # and a block list. The release job uses a block list. Read only inside the
  # one jobs mapping, for the same reason as job_block.
  job_needs() {
    awk -v job="$2" '
      BEGIN { in_jobs = 0; found = 0; inblock = 0; inlist = 0 }
      /^jobs:[ \t]*$/ { in_jobs = 1; next }
      !in_jobs { next }
      /^#/ { next }
      /^[^ \t]/ { exit }
      $0 == "  " job ":" { inblock = 1; found = 1; inlist = 0; next }
      inblock && /^  [A-Za-z0-9_-]+:[ \t]*$/ { exit }
      inblock && /^[ \t]*$/ { next }
      inblock && /^  #/ { next }
      inblock && /^    needs: \[/ {
        line = $0
        sub(/^    needs: \[/, "", line)
        sub(/\].*$/, "", line)
        count = split(line, parts, ",")
        for (i = 1; i <= count; i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", parts[i])
          if (parts[i] != "") print parts[i]
        }
        inlist = 0
        next
      }
      inblock && /^    needs:[ \t]*$/ { inlist = 1; next }
      inlist && /^[ \t]*$/ { next }
      inlist && /^[ \t]+#[ \t]*/ { next }
      # A block sequence may sit at the key indentation (four spaces) or one
      # level deeper (six spaces). Both are valid YAML and GitHub reads the
      # same edges. Read both spellings so a same-indent list cannot hide a
      # dependency from the prerequisite check.
      inlist && /^      - / {
        line = $0
        sub(/^      - /, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") print line
        next
      }
      inlist && /^    - / {
        line = $0
        sub(/^    - /, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") print line
        next
      }
      inlist && /^    [A-Za-z0-9_-]+:/ { inlist = 0 }
    ' "$1"
  }

  # List the job ids in the one jobs mapping. This cannot read a decoy header
  # from a top-level block scalar or a second jobs mapping.
  workflow_job_ids() {
    awk '
      BEGIN { in_jobs = 0 }
      /^jobs:[ \t]*$/ { in_jobs = 1; next }
      !in_jobs { next }
      /^#/ { next }
      /^[^ \t]/ { exit }
      /^  [A-Za-z0-9_-]+:[ \t]*$/ {
        id = $0
        sub(/^  /, "", id)
        sub(/:[ \t]*$/, "", id)
        print id
      }
    ' "$1"
  }

  required_jobs='rust-macos rust-windows rust-linux desktop-demo desktop-windows winui-demo android-demo ios macos-app lint release-audit verify-macos-binary verify-ios-ipa verify-macos-app artifact-integrity release'
  missing_jobs=""
  job_ids=$(workflow_job_ids "$workflow")
  for job in $required_jobs; do
    printf '%s\n' "$job_ids" | grep -x "$job" >/dev/null || missing_jobs="$missing_jobs $job"
  done
  if [ -n "$missing_jobs" ]; then
    fail "ci.yml is missing job:$missing_jobs"
  else
    pass "ci.yml defines the required jobs"
  fi

  needs=$(job_needs "$workflow" release)
  if [ -z "$needs" ]; then
    fail "the release job has no needs list"
  else
    missing_needs=""
    for job in rust-macos rust-windows rust-linux desktop-demo desktop-windows winui-demo android-demo ios macos-app lint release-audit verify-macos-binary verify-ios-ipa verify-macos-app artifact-integrity; do
      printf '%s\n' "$needs" | grep -x "$job" >/dev/null || missing_needs="$missing_needs $job"
    done
    if [ -n "$missing_needs" ]; then
      fail "the release job does not wait for:$missing_needs"
    else
      pass "the release job waits for every required job"
    fi
  fi

  release_block=$(job_block "$workflow" release)
  # The publish job has write permission. Treat any structural change as a
  # policy change requiring review, including YAML spellings the checks below
  # do not parse. Keep the expected block in sync only after that review.
  if [ -f "$root/scripts/release_job.expected" ] &&
     [ "$release_block" = "$(cat "$root/scripts/release_job.expected")" ]; then
    pass "the release job matches the reviewed policy block"
  else
    fail "the release job differs from the reviewed policy block"
  fi
  if printf '%s\n' "$release_block" | grep -xF "    if: startsWith(github.ref, 'refs/tags/v')" >/dev/null; then
    pass "the release job only runs for a v tag after successful prerequisites"
  else
    fail "the release job must use the v-tag condition without a status override"
  fi
  if printf '%s\n' "$release_block" | grep -xF '        run: sh scripts/release_audit.sh --artifacts release --tag "$GITHUB_REF_NAME" --require-aligned-versions' >/dev/null; then
    pass "the release job runs the strict tagged release audit"
  else
    fail "the release job must run the strict tagged release audit without an override"
  fi
  if printf '%s\n' "$release_block" | grep -xF '        run: sh scripts/release_manifest.sh --verify release' >/dev/null; then
    pass "the release job verifies the checksum manifest"
  else
    fail "the release job must verify the checksum manifest without an override"
  fi
  if printf '%s\n' "$release_block" | grep 'SHA256SUMS' >/dev/null; then
    pass "the release job publishes SHA256SUMS"
  else
    fail "the release job does not publish SHA256SUMS"
  fi
  if printf '%s\n' "$release_block" | grep -- '--verify-tag' >/dev/null; then
    pass "the release job verifies the tag instead of creating it"
  else
    fail "the release job does not pass --verify-tag to gh release create"
  fi

  # The exact blocks above are the reviewed source of truth. This check states
  # the digest chain explicitly, so a reviewed block that loses an output or a
  # consumer step fails instead of silently passing the block comparison.
  digest_bad=0
  for verifier in verify-macos-binary verify-ios-ipa verify-macos-app; do
    block=$(job_block "$workflow" "$verifier")
    printf '%s\n' "$block" | grep -xF '        value: ${{ steps.digest.outputs.sha256 }}' >/dev/null || digest_bad=1
    printf '%s\n' "$block" | grep -xF '      - name: Record the verified artifact digest' >/dev/null || digest_bad=1
  done
  integrity_block=$(job_block "$workflow" artifact-integrity)
  printf '%s\n' "$integrity_block" | grep -xF '        value: ${{ steps.manifest.outputs.sha256 }}' >/dev/null || digest_bad=1
  printf '%s\n' "$integrity_block" | grep -F 'sh scripts/release_manifest.sh --expect "$BINARY_SHA256"' >/dev/null || digest_bad=1
  printf '%s\n' "$release_block" | grep -xF '          MANIFEST_SHA256: ${{ needs.artifact-integrity.outputs.manifest-sha256 }}' >/dev/null || digest_bad=1
  printf '%s\n' "$release_block" | grep -xF '          sh scripts/release_manifest.sh --expect "$MANIFEST_SHA256" release/SHA256SUMS' >/dev/null || digest_bad=1
  if [ "$digest_bad" -eq 0 ]; then
    pass "verifier digests feed artifact-integrity and the release checks the manifest digest"
  else
    fail "the release digest binding is incomplete"
  fi

  actual_create=$(printf '%s\n' "$release_block" | awk '
    /^          gh release create / { in_command = 1 }
    in_command { print; if ($0 !~ /\\$/) exit }
  ')
  expected_create=$(printf '%s\n' \
    '          gh release create "${GITHUB_REF_NAME}" \' \
    '            --repo "${GITHUB_REPOSITORY}" \' \
    '            --verify-tag \' \
    '            --title "${GITHUB_REF_NAME}" \' \
    '            --notes "$NOTES" \' \
    '            release/hotspotshade-macos-arm64.bin \' \
    '            release/HotspotShade-iOS-unsigned.ipa \' \
    '            release/HotspotShade-unsigned.zip \' \
    '            release/SHA256SUMS \' \
    '            release/PROVENANCE.txt')
  if [ "$actual_create" = "$expected_create" ]; then
    pass "the release job publishes only the audited artifact set"
  else
    fail "the release command must publish exactly the audited artifact set"
  fi

  # Check every release run block, in order. Checking only for the presence of
  # the expected commands would permit an earlier publish or a later upload.
  actual_runs=$(printf '%s\n' "$release_block" | awk '
    BEGIN { run_ind = -1 }
    function indent_of(s) { match(s, /^ */); return RLENGTH }
    /^      -[[:space:]]+run[[:space:]]*:/ { print; run_ind = 8; next }
    /^        run:/ { run_ind = 8; print; next }
    run_ind >= 0 {
      if (indent_of($0) > run_ind) { print; next }
      run_ind = -1
    }
  ')
  expected_runs=$(printf '%s\n' \
    '        run: |' \
    '          sh scripts/release_manifest.sh --expect "$BINARY_SHA256" release/hotspotshade-macos-arm64.bin' \
    '          sh scripts/release_manifest.sh --expect "$IPA_SHA256" release/HotspotShade-iOS-unsigned.ipa' \
    '          sh scripts/release_manifest.sh --expect "$APP_SHA256" release/HotspotShade-unsigned.zip' \
    '          sh scripts/release_manifest.sh --expect "$MANIFEST_SHA256" release/SHA256SUMS' \
    '        run: sh scripts/release_audit.sh --artifacts release --tag "$GITHUB_REF_NAME" --require-aligned-versions' \
    '        run: sh scripts/release_manifest.sh --verify release' \
    '        run: |' \
    "$expected_create")
  if [ "$actual_runs" = "$expected_runs" ] &&
     ! printf '%s\n' "$release_block" | grep -E "^      [[:space:]]*(-[[:space:]]+)?['\"]?if['\"]?[[:space:]]*:" >/dev/null; then
    pass "release runs only the ordered, unconditional audit, manifest, and publish steps"
  else
    fail "release commands must be unconditional and match the audited order"
  fi

  # Build jobs produce the files that a release publishes. Exact block matches
  # keep a build command, an environment entry, or an upload target from
  # changing without a matching review of the expected file. The policy job is
  # matched for the same reason: it must keep running the audit and the graph
  # check. A test job produces no release artifact; the upload allowlist below
  # still stops it from writing a release artifact name.
  for spec in \
    'lint|scripts/lint_job.expected|        run: cargo clippy --all-targets --locked -- -D warnings' \
    'rust-macos|scripts/rust_macos_job.expected|        run: cargo build --release --locked' \
    'rust-windows|scripts/rust_windows_job.expected|        run: cargo test --locked' \
    'rust-linux|scripts/rust_linux_job.expected|        run: cargo build --locked --manifest-path rust/Cargo.toml' \
    'desktop-demo|scripts/desktop_demo_job.expected|        run: cargo test --locked --manifest-path desktop/Cargo.toml' \
    'desktop-windows|scripts/desktop_windows_job.expected|        run: cargo test --locked --manifest-path desktop/Cargo.toml' \
    'winui-demo|scripts/winui_demo_job.expected|        run: dotnet run --project windows/tests/HotspotShade.WinUI2.Core.Tests/HotspotShade.WinUI2.Core.Tests.csproj --configuration Release' \
    'android-demo|scripts/android_demo_job.expected|        run: ./gradlew --no-daemon testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest' \
    'ios|scripts/ios_job.expected|        run: scripts/build_ipa.sh build/HotspotShade-iOS-unsigned.ipa' \
    'macos-app|scripts/macos_app_job.expected|        run: scripts/build_mac_app.sh build/HotspotShade-unsigned.zip' \
    'release-audit|scripts/release_audit_job.expected|        run: sh scripts/release_audit.sh' \
    'verify-macos-binary|scripts/verify_macos_binary_job.expected|        run: sh scripts/release_audit.sh --artifacts artifact' \
    'verify-ios-ipa|scripts/verify_ios_ipa_job.expected|        run: sh scripts/release_audit.sh --artifacts artifact' \
    'verify-macos-app|scripts/verify_macos_app_job.expected|        run: sh scripts/release_audit.sh --artifacts artifact --check-codesign' \
    'artifact-integrity|scripts/artifact_integrity_job.expected|        run: sh scripts/release_manifest.sh --verify release'; do
    job=${spec%%|*}
    rest=${spec#*|}
    expected_rel=${rest%%|*}
    command=${rest#*|}
    block=$(job_block "$workflow" "$job")
    expected_path=$root/$expected_rel
    if [ ! -f "$expected_path" ]; then
      fail "$job has no reviewed policy block at $expected_rel"
    elif [ "$block" = "$(cat "$expected_path")" ]; then
      pass "$job matches the reviewed policy block"
    else
      fail "$job differs from the reviewed policy block; do not hide a command in a block scalar, change its shell, or add a step before it"
    fi
    if ! printf '%s\n' "$block" | grep -xF "$command" >/dev/null; then
      fail "$job is missing its required verification command"
    fi
    # A step condition can skip a verification command. The one allowed
    # condition is the cache tag guard, and the exact block match already
    # pins it to the cache step. Any other condition fails.
    other_conditions=$(printf '%s\n' "$block" |
      grep -E "^[[:space:]]+(-[[:space:]]+)?['\"]?if['\"]?[[:space:]]*:" |
      grep -vxF "        if: github.ref_type != 'tag'" || true)
    if [ -n "$other_conditions" ]; then
      fail "$job must not conditionally skip verification"
    fi
  done

  if grep -i 'continue-on-error' "$workflow" >/dev/null; then
    fail "ci.yml uses continue-on-error"
  else
    pass "no job continues on error"
  fi
  if grep -i 'pull_request_target' "$workflow" >/dev/null; then
    fail "ci.yml uses pull_request_target"
  else
    pass "ci.yml does not use pull_request_target"
  fi
  run_workflow_scan workflow_job_structure "the workflow job structure check"
  run_workflow_scan workflow_scan_policy "the action pin and permission scan"

fi

# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

# Print the entry names of a zip file. Return the unzip status: a listing that
# could not be read is not an empty archive, and the caller must fail closed.
zip_entries() {
  unzip -Z1 "$1" 2>/dev/null
}

# Extract one archive entry into DEST. Return zero only when unzip succeeded
# and the entry is not empty. The content is never printed.
zip_entry_to_file() {
  if ! unzip -p "$1" "$2" > "$3" 2>/dev/null; then
    return 1
  fi
  [ -s "$3" ]
}

# Print the ten-character Unix mode for one exact archive entry, or nothing
# when the listing has no match. A failure to list is not a match.
zip_entry_mode() {
  mode_listing=$(mktemp "${TMPDIR:-/tmp}/hs-zip-list.XXXXXX") || return 1
  if ! unzip -Z -l "$1" > "$mode_listing" 2>/dev/null; then
    rm -f "$mode_listing"
    return 1
  fi
  awk -v want="$2" '
    length($0) >= length(want) &&
    substr($0, length($0) - length(want) + 1) == want {
      print substr($0, 1, 10)
      exit
    }
  ' "$mode_listing"
  rm -f "$mode_listing"
  return 0
}

# A ZIP may list every entry and still fail a CRC or a truncated entry stream.
# unzip -t is the integrity test; its output holds file names, so discard it.
check_zip_integrity() {
  if ! command -v unzip >/dev/null 2>&1; then
    fail "${2}: unzip is unavailable; the archive cannot be read"
    return 1
  fi
  if ! unzip -t "$1" >/dev/null 2>&1; then
    fail "${2}: the archive is corrupt or cannot be read"
    return 1
  fi
  pass "${2}: the archive passes an integrity test"
  return 0
}

check_archive_paths() {
  # Reject ambiguous extraction paths and symlinks before any extraction.
  archive_paths_safe=yes
  if printf '%s\n' "$entries" | awk '
    /^\// || /(^|\/)\.\.(\/|$)/ || index($0, "\\") { bad = 1 }
    END { exit bad }
  '; then
    pass "${2}: the archive has no absolute, parent, or backslash paths"
  else
    fail "${2}: the archive contains an unsafe path"
    archive_paths_safe=no
  fi
  symlink_listing=$(mktemp "${TMPDIR:-/tmp}/hs-zip-list.XXXXXX") || {
    fail "${2}: cannot create a temporary file to inspect the archive"
    archive_paths_safe=no
    return
  }
  if ! unzip -Z -l "$1" > "$symlink_listing" 2>/dev/null; then
    fail "${2}: unzip cannot read the archive metadata"
    archive_paths_safe=no
    rm -f "$symlink_listing"
    return
  fi
  if grep '^l' "$symlink_listing" >/dev/null 2>&1; then
    symlink_status=0
  else
    symlink_status=$?
  fi
  case "$symlink_status" in
    0)
      fail "${2}: the archive contains a symbolic link"
      archive_paths_safe=no
      ;;
    1)
      pass "${2}: the archive contains no symbolic links"
      ;;
    *)
      fail "${2}: the archive metadata could not be inspected"
      archive_paths_safe=no
      ;;
  esac
  rm -f "$symlink_listing"
}

# Compare one artifact version with the engine version. An unreadable version
# is a release blocker: a strict release must not treat a missing artifact
# version as aligned.
artifact_version_note() {
  # artifact_version_note LABEL VERSION
  if [ -z "$2" ]; then
    release_blocker "$1: the artifact version cannot be verified from its bytes; a strict release fails closed"
    return
  fi
  if [ -z "$engine_version" ]; then
    fail "cannot compare the artifact version: the engine version is unknown: $1"
    return
  fi
  version_note "$1" "$2"
}

# Check the structure of an app Info.plist and read its bundle version where
# this host can. An XML plist is read by the dependency-free plist reader. A
# binary plist needs plutil; without it only the magic and nonempty input are
# checked, so its structure and version stay unverified and strict release fails.
check_app_plist() {
  # check_app_plist ZIP ENTRY LABEL
  plist_tmp=$(mktemp "${TMPDIR:-/tmp}/hs-zip-plist.XXXXXX") || {
    fail "${3}: cannot create a temporary file for the app Info.plist"
    return
  }
  if ! zip_entry_to_file "$1" "$2" "$plist_tmp"; then
    fail "${3}: the app bundle has no nonempty Info.plist"
    rm -f "$plist_tmp"
    return
  fi
  plist_magic=$(od -An -v -tx1 -N8 "$plist_tmp" 2>/dev/null | tr -d ' \n')
  plist_value=""
  case "$plist_magic" in
    62706c6973743030)
      if command -v plutil >/dev/null 2>&1; then
        if ! plutil -lint "$plist_tmp" >/dev/null 2>&1; then
          fail "${3}: the app Info.plist is a malformed binary plist"
          rm -f "$plist_tmp"
          return
        fi
        plist_value=$(plutil -extract CFBundleShortVersionString raw -o - "$plist_tmp" 2>/dev/null || true)
      fi
      pass "${3}: the app bundle has a nonempty binary Info.plist"
      ;;
    *)
      if plist_value=$(plist_version "$plist_tmp" CFBundleShortVersionString 2>/dev/null); then
        pass "${3}: the app bundle has a nonempty XML Info.plist with a bundle version"
      else
        fail "${3}: the app Info.plist is not a readable XML plist with CFBundleShortVersionString"
        rm -f "$plist_tmp"
        return
      fi
      ;;
  esac
  rm -f "$plist_tmp"
  artifact_version_note "${3}: CFBundleShortVersionString" "$plist_value"
}

check_app_executable() {
  # check_app_executable ZIP ENTRY LABEL PLATFORM
  exe_tmp=$(mktemp "${TMPDIR:-/tmp}/hs-zip-exe.XXXXXX") || {
    fail "${3}: cannot create a temporary file for the app executable"
    return
  }
  if ! zip_entry_to_file "$1" "$2" "$exe_tmp"; then
    fail "${3}: the app bundle has no nonempty executable ${2}"
    rm -f "$exe_tmp"
    return
  fi
  mode=$(zip_entry_mode "$1" "$2" 2>/dev/null || true)
  case "$mode" in
    -*x*)
      pass "${3}: the app executable is marked executable"
      check_macho "$exe_tmp" "$3" "$4" "app executable"
      ;;
    '')
      fail "${3}: the executable mode for ${2} could not be read"
      ;;
    *)
      fail "${3}: the app executable ${2} is not marked executable"
      ;;
  esac
  rm -f "$exe_tmp"
}

check_ipa() {
  # check_ipa PATH
  if ! check_zip_integrity "$1" "$2"; then
    return
  fi
  if ! entries=$(zip_entries "$1"); then
    fail "${2}: unzip cannot list the archive"
    return
  fi
  if [ -z "$entries" ]; then
    fail "${2}: unzip cannot list the archive"
    return
  fi
  check_archive_paths "$1" "$2"
  if ! printf '%s\n' "$entries" | awk '
    BEGIN { bad = 0; under = 0 }
    {
      e = $0
      want = "Payload/HotspotProxy.app/"
      if (e == "Payload/" || e == "Payload/HotspotProxy.app" || e == want) { under = 1; next }
      if (index(e, want) == 1) {
        rest = substr(e, length(want) + 1)
        if (rest == "") { under = 1; next }
        if (tolower(rest) ~ /[.]app([\/]|$)/) { bad = 1; exit }
        under = 1
        next
      }
      bad = 1
    }
    END { if (bad || !under) exit 1 }
  '; then
    fail "${2}: the IPA must hold exactly one app bundle at Payload/HotspotProxy.app"
  else
    pass "${2}: the IPA holds exactly one app bundle at Payload/HotspotProxy.app"
  fi
  if printf '%s\n' "$entries" | grep -Ei '_CodeSignature|embedded\.mobileprovision|/SC_Info/|\.(p12|pfx|cer|crt|key|pem|p8|ppk|mobileprovision|provisionprofile)$' >/dev/null; then
    fail "${2}: the IPA holds signing material; a release IPA must be unsigned"
  else
    pass "${2}: the IPA is unsigned and holds no provisioning profile"
  fi
  check_app_plist "$1" "Payload/HotspotProxy.app/Info.plist" "$2"
  check_app_executable "$1" "Payload/HotspotProxy.app/HotspotProxy" "$2" ios
}

check_mac_zip() {
  # check_mac_zip PATH
  archive_paths_safe=no
  if ! check_zip_integrity "$1" "$2"; then
    return
  fi
  if ! entries=$(zip_entries "$1"); then
    fail "${2}: unzip cannot list the archive"
    return
  fi
  if [ -z "$entries" ]; then
    fail "${2}: unzip cannot list the archive"
    return
  fi
  check_archive_paths "$1" "$2"
  if ! printf '%s\n' "$entries" | awk '
    BEGIN { bad = 0; under = 0 }
    {
      e = $0
      want = "HotspotShade.app/"
      if (e == "HotspotShade.app" || e == want) { under = 1; next }
      if (index(e, want) == 1) {
        rest = substr(e, length(want) + 1)
        if (rest == "") { under = 1; next }
        if (tolower(rest) ~ /[.]app([\/]|$)/) { bad = 1; exit }
        under = 1
        next
      }
      bad = 1
    }
    END { if (bad || !under) exit 1 }
  '; then
    fail "${2}: the archive must hold exactly one app bundle at HotspotShade.app"
  else
    pass "${2}: the archive holds exactly one app bundle at HotspotShade.app"
  fi
  if printf '%s\n' "$entries" | grep -Ei 'embedded\.provisionprofile|\.mobileprovision|\.(p12|pfx|cer|crt|key|pem|p8|ppk|mobileprovision|provisionprofile)$|identity\.key' >/dev/null; then
    fail "${2}: the app archive holds signing material or an identity key"
  else
    pass "${2}: the app archive holds no provisioning profile or identity key"
  fi
  if printf '%s\n' "$entries" | grep '_CodeSignature/' >/dev/null; then
    pass "${2}: the app archive contains a signature entry; its authority is not established by this check"
  else
    warn "${2}: the app carries no signature"
  fi
  check_app_plist "$1" "HotspotShade.app/Contents/Info.plist" "$2"
  check_app_executable "$1" "HotspotShade.app/Contents/MacOS/HotspotShade" "$2" macos
}

# Validate a little-endian 64-bit arm64 Mach-O executable. PLATFORM is macos,
# ios, or any. KIND names the file in a person-facing message. The reader
# checks the header, every load-command boundary, the segment file extents, and
# that the LC_MAIN entry point lies after the header and load commands inside a
# nonempty executable segment. When the file declares its build platform, that
# platform must match the artifact. A header-only, truncated, or stub file is
# rejected.
check_macho() {
  # check_macho FILE LABEL PLATFORM KIND
  macho_file=$1
  macho_label=$2
  macho_platform=$3
  macho_kind=$4
  size=$(wc -c < "$macho_file" 2>/dev/null | tr -d ' ' || true)
  # -v keeps a repeated 16-byte row in the output. Without it od writes "*"
  # for a repeated row, and a valid file with repeated load-command rows
  # would fail the length check below.
  header=$(od -An -v -tx1 -N32 "$macho_file" 2>/dev/null | tr -d ' \n')
  prefix=$(printf '%s' "$header" | cut -c 1-16)
  filetype=$(printf '%s' "$header" | cut -c 25-32)
  if [ "$prefix" = "cffaedfe0c000001" ] && [ "$filetype" = "02000000" ]; then
    if [ -z "$size" ] || [ "$size" -lt 4096 ]; then
      fail "${macho_label}: the ${macho_kind} is implausibly truncated for a Mach-O executable"
      return
    fi
    layout=$(printf '%s\n' "$header" | awk '
      function hex_value(s,   n) {
        n = index("0123456789abcdef", tolower(s))
        return n - 1
      }
      function hex_byte(s,   a, b) {
        a = hex_value(substr(s, 1, 1))
        b = hex_value(substr(s, 2, 1))
        if (a < 0 || b < 0) return -1
        return a * 16 + b
      }
      function le32(h, byteoff,   p, b1, b2, b3, b4) {
        p = (byteoff - 1) * 2
        b1 = hex_byte(substr(h, p + 1, 2))
        b2 = hex_byte(substr(h, p + 3, 2))
        b3 = hex_byte(substr(h, p + 5, 2))
        b4 = hex_byte(substr(h, p + 7, 2))
        if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0) return -1
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      }
      { h = $0 }
      END {
        ncmds = le32(h, 17)
        sizeofcmds = le32(h, 21)
        if (ncmds < 0 || sizeofcmds < 0) exit 1
        printf "%d %d\n", ncmds, sizeofcmds
      }
    ') || true
    ncmds=${layout%% *}
    sizeofcmds=${layout##* }
    if [ -z "$layout" ] || [ -z "$ncmds" ] || [ -z "$sizeofcmds" ]; then
      fail "${macho_label}: the ${macho_kind} has no readable Mach-O header"
      return
    fi
    if [ "$ncmds" -lt 1 ] || [ "$sizeofcmds" -lt 8 ] ||
       [ "$sizeofcmds" -gt 1048576 ] || [ $((sizeofcmds % 8)) -ne 0 ] ||
       [ $((32 + sizeofcmds)) -gt "$size" ]; then
      fail "${macho_label}: the ${macho_kind} is implausibly truncated for a Mach-O executable"
      return
    fi
    commands=$(od -An -v -tx1 -j 32 -N "$sizeofcmds" "$macho_file" 2>/dev/null | tr -d ' \n')
    if [ "${#commands}" -ne $((sizeofcmds * 2)) ]; then
      fail "${macho_label}: the ${macho_kind} is implausibly truncated for a Mach-O executable"
      return
    fi
    if printf '%s\n' "$commands" | awk -v want_ncmds="$ncmds" -v want_sizeofcmds="$sizeofcmds" -v file_size="$size" -v want_platform="$macho_platform" '
      function hex_value(s,   n) {
        n = index("0123456789abcdef", tolower(s))
        return n - 1
      }
      function hex_byte(s,   a, b) {
        a = hex_value(substr(s, 1, 1))
        b = hex_value(substr(s, 2, 1))
        if (a < 0 || b < 0) return -1
        return a * 16 + b
      }
      function le32(h, byteoff,   p, b1, b2, b3, b4) {
        p = (byteoff - 1) * 2
        b1 = hex_byte(substr(h, p + 1, 2))
        b2 = hex_byte(substr(h, p + 3, 2))
        b3 = hex_byte(substr(h, p + 5, 2))
        b4 = hex_byte(substr(h, p + 7, 2))
        if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0) return -1
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
      }
      { h = $0 }
      END {
        len = length(h) / 2
        if (len != want_sizeofcmds) exit 1
        pos = 1
        count = 0
        segments = 0
        main = 0
        total = 0
        entryoff = -1
        build_seen = 0
        platform_ok = 0
        version_min_ok = 0
        expected = (want_platform == "macos" ? 1 : (want_platform == "ios" ? 2 : 0))
        while (pos <= len) {
          if (len - pos + 1 < 8) exit 1
          cmd = le32(h, pos)
          cmdsize = le32(h, pos + 4)
          if (cmd < 0 || cmdsize < 8 || cmdsize % 8 != 0) exit 1
          if (pos + cmdsize - 1 > len) exit 1
          count++
          total += cmdsize
          if (cmd == 25) {
            if (cmdsize < 72) exit 1
            if (le32(h, pos + 44) != 0 || le32(h, pos + 52) != 0) exit 1
            fileoff = le32(h, pos + 40)
            filesize = le32(h, pos + 48)
            segments++
            if (fileoff < 0 || filesize < 0) exit 1
            if (filesize > 0 && (fileoff > file_size || filesize > file_size - fileoff)) exit 1
            seg_off[segments] = fileoff
            seg_size[segments] = filesize
            seg_prot[segments] = le32(h, pos + 60)
            if (seg_prot[segments] < 0) exit 1
          } else if (cmd == 2147483688) {
            if (cmdsize < 24 || main) exit 1
            if (le32(h, pos + 12) != 0) exit 1
            entryoff = le32(h, pos + 8)
            # The entry point is a file offset inside the file, not EOF.
            if (entryoff < 0 || entryoff >= file_size) exit 2
            # A real executable entry point starts after the Mach-O header and
            # load commands. An entry at offset zero points at the header.
            if (entryoff < 32 + want_sizeofcmds) exit 3
            main = 1
          } else if (cmd == 29) {
            if (cmdsize < 16) exit 1
            dataoff = le32(h, pos + 8)
            datasize = le32(h, pos + 12)
            if (dataoff < 0 || datasize < 0) exit 1
            if (datasize > 0 && (dataoff > file_size || datasize > file_size - dataoff)) exit 1
          } else if (cmd == 50) {
            # LC_BUILD_VERSION: platform at offset 8. More than one is
            # ambiguous. The expected platform is macOS (1) or iOS (2).
            if (cmdsize < 24 || build_seen) exit 1
            build_seen = 1
            platform = le32(h, pos + 8)
            if (platform < 0) exit 1
            if (expected > 0) platform_ok = (platform == expected ? 1 : -1)
          } else if (cmd == 36 || cmd == 37) {
            # LC_VERSION_MIN_MACOSX and LC_VERSION_MIN_IPHONEOS are the older
            # platform declaration. Accept one only when no LC_BUILD_VERSION
            # is present.
            if (cmdsize < 16) exit 1
            if (expected == 1 && cmd == 36) version_min_ok = 1
            if (expected == 2 && cmd == 37) version_min_ok = 1
          }
          pos += cmdsize
        }
        if (count != want_ncmds || total != want_sizeofcmds) exit 1
        if (segments < 1 || !main || entryoff < 0) exit 1
        if (expected > 0) {
          if (build_seen) {
            if (platform_ok != 1) exit 4
          } else if (!version_min_ok) {
            exit 4
          }
        }
        # The entry point must lie in a segment that has bytes and execute
        # permission. An entry in a zero-size or non-executable segment is not
        # a runnable executable image.
        found = 0
        exec_ok = 0
        for (s = 1; s <= segments; s++) {
          if (seg_size[s] <= 0) continue
          if (entryoff >= seg_off[s] && entryoff < seg_off[s] + seg_size[s]) {
            found = 1
            if (int(seg_prot[s] / 4) % 2 == 1) exec_ok = 1
          }
        }
        if (!found || !exec_ok) exit 2
      }
    '; then
      pass "${macho_label}: the ${macho_kind} is a Mach-O arm64 executable"
    else
      macho_status=$?
      case "$macho_status" in
        2)
          fail "${macho_label}: the ${macho_kind} entry point is not inside a nonempty executable segment"
          ;;
        3)
          fail "${macho_label}: the ${macho_kind} entry point overlaps the header or load commands"
          ;;
        4)
          fail "${macho_label}: the ${macho_kind} does not declare the expected ${macho_platform} platform"
          ;;
        *)
          fail "${macho_label}: the ${macho_kind} is implausibly truncated or has invalid load commands"
          ;;
      esac
      return
    fi
  elif [ "$prefix" = "cffaedfe07000001" ]; then
    fail "${macho_label}: the ${macho_kind} is x86_64; the release is arm64 only"
  elif [ "$(printf '%s' "$prefix" | cut -c 1-8)" = "cafebabe" ]; then
    fail "${macho_label}: the ${macho_kind} is a universal archive; the release is arm64 only"
  else
    fail "${macho_label}: the ${macho_kind} is not a Mach-O arm64 executable"
  fi
}

check_mac_binary() {
  # The release binary is little-endian Mach-O 64 with CPU type arm64 and
  # filetype MH_EXECUTE. An arm64 dylib has the same first eight bytes. Check
  # the load commands, the platform, and the segment extents too, so a
  # header-only, stub, or truncated file cannot pass as an executable.
  check_macho "$1" "$2" macos "binary"
}

check_codesign_bundle() {
  # check_codesign_bundle ZIP
  if ! command -v codesign >/dev/null 2>&1; then
    fail "${2}: codesign is unavailable; the requested signature check cannot run"
    return
  fi
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/hs-codesign.XXXXXX")
  if ! ditto -x -k "$1" "$tmp" >/dev/null 2>&1; then
    fail "${2}: cannot extract the app archive for a signature check"
    rm -rf "$tmp"
    return
  fi
  app=$tmp/HotspotShade.app
  if [ ! -d "$app" ]; then
    fail "${2}: the archive holds no HotspotShade.app bundle"
    rm -rf "$tmp"
    return
  fi
  if ! extra=$(find "$tmp" -name '*.app' -type d ! -path "$app" -print 2>/dev/null); then
    fail "${2}: cannot enumerate the extracted app bundles"
    rm -rf "$tmp"
    return
  fi
  if [ -n "$extra" ]; then
    fail "${2}: the archive holds more than one app bundle"
    rm -rf "$tmp"
    return
  fi
  if ! extra_top=$(find "$tmp" -mindepth 1 -maxdepth 1 ! -name 'HotspotShade.app' -print 2>/dev/null); then
    fail "${2}: cannot enumerate the extracted archive entries"
    rm -rf "$tmp"
    return
  fi
  if [ -n "$extra_top" ]; then
    fail "${2}: the archive holds an entry outside HotspotShade.app"
    rm -rf "$tmp"
    return
  fi
  if codesign --verify --deep --strict "$app" >/dev/null 2>&1; then
    pass "${2}: the app bundle passes codesign --verify"
  else
    fail "${2}: the app bundle fails codesign --verify"
  fi
  details=$(codesign -dv --verbose=4 "$app" 2>&1 || true)
  case "$details" in
    *Signature=adhoc*) pass "${2}: the app is ad-hoc signed, not notarized" ;;
    *"Authority=Developer ID"*) fail "${2}: the app has a Developer ID signature, but this workflow expects ad-hoc signing" ;;
    *) fail "${2}: the app signature could not be established as ad hoc" ;;
  esac
  rm -rf "$tmp"
}

verify_sums() {
  # Use the same complete-set verifier as the release workflow. This must
  # reject unlisted files as well as missing or modified listed files.
  if result=$(sh "$root/scripts/release_manifest.sh" --verify "$1" 2>&1); then
    pass "SHA256SUMS matches the complete artifact set"
  else
    case "$result" in
      *MISMATCH*) fail "digest mismatch: $result" ;;
      *) fail "invalid SHA256SUMS: $result" ;;
    esac
  fi
}

if [ -n "$artifacts" ]; then
  if [ ! -d "$artifacts" ]; then
    fail "artifact directory is missing: $artifacts"
  else
    seen=0
    for path in "$artifacts"/*; do
      [ -e "$path" ] || continue
      [ -f "$path" ] || continue
      name=$(basename "$path")
      case "$name" in
        SHA256SUMS)
          seen=$((seen + 1))
          verify_sums "$artifacts"
          ;;
        PROVENANCE.txt)
          seen=$((seen + 1))
          if [ -n "$tag" ]; then
            commit=$(sed -n 's/^Commit: //p' "$path")
            case "$commit" in
              *[!0-9a-f]*|'') valid_commit=no ;;
              *) valid_commit=yes ;;
            esac
            if [ "$valid_commit" != yes ] || [ "${#commit}" -ne 40 ]; then
              fail "$name: tagged release provenance must name a full commit SHA"
            elif [ -n "${GITHUB_SHA:-}" ] && [ "$commit" != "$GITHUB_SHA" ]; then
              fail "$name: provenance commit does not match the workflow commit"
            else
              pass "$name: tagged release provenance names the workflow commit"
            fi
          elif grep '^Commit: ' "$path" >/dev/null; then
            pass "$name: the provenance record names a commit"
          else
            fail "$name: the provenance record has no commit"
          fi
          ;;
        *.ipa)
          seen=$((seen + 1))
          check_ipa "$path" "$name"
          ;;
        *.zip)
          seen=$((seen + 1))
          check_mac_zip "$path" "$name"
          if [ "$check_codesign" -eq 1 ]; then
            if [ "${archive_paths_safe:-no}" = yes ]; then
              check_codesign_bundle "$path" "$name"
            else
              fail "$name: refusing to extract an unsafe archive for signature verification"
            fi
          fi
          ;;
        hotspotshade|hotspotshade-macos-*)
          seen=$((seen + 1))
          check_mac_binary "$path" "$name"
          release_blocker "$name: the standalone binary carries no readable version; a strict release cannot verify its version from its bytes"
          ;;
        *.deb)
          seen=$((seen + 1))
          warn "$name: a .deb has no signature; the release notes must say it is unsigned"
          ;;
        *.apk)
          seen=$((seen + 1))
          warn "$name: an APK in the release set is a debug build; check the release notes"
          ;;
        *)
          warn "$name: not a recognized release artifact"
          ;;
      esac
    done
    if [ "$seen" -eq 0 ]; then
      fail "the artifact directory holds no release artifact"
    fi
    # App bundle versions are checked from the Info.plist where this host can
    # read the plist. A binary plist needs plutil; without it the version is
    # unverified and the strict release fails closed. The standalone binary's
    # version cannot yet be verified from its bytes by this audit either.
    if [ -n "$tag" ]; then
      # The tag release has a fixed set. A self-consistent but incomplete
      # manifest must not make a missing release artifact look valid.
      for required in hotspotshade-macos-arm64.bin HotspotShade-iOS-unsigned.ipa HotspotShade-unsigned.zip SHA256SUMS PROVENANCE.txt; do
        if [ ! -f "$artifacts/$required" ] || [ -L "$artifacts/$required" ]; then
          fail "the tagged release is missing a regular file: $required"
        fi
      done
      for path in "$artifacts"/* "$artifacts"/.[!.]* "$artifacts"/..?*; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        case "$(basename "$path")" in
          hotspotshade-macos-arm64.bin|HotspotShade-iOS-unsigned.ipa|HotspotShade-unsigned.zip|SHA256SUMS|PROVENANCE.txt) ;;
          *) fail "unexpected file in tagged release: $(basename "$path")" ;;
        esac
      done
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "Summary: $passes passed, $warnings warned, $failures failed"

if [ "$failures" -gt 0 ]; then
  echo "The release audit failed. Fix every FAIL line before you tag a release."
  exit 1
fi

if [ "$warnings" -gt 0 ]; then
  echo "The release audit passed with warnings. Read every WARN line."
else
  echo "The release audit passed."
fi
exit 0
