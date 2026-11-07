#!/bin/sh
# Validate and print the CI job dependency graph.
#
# The script reads the `# ci-stage:` tag above each job and the `needs:` list
# of each job in .github/workflows/ci.yml. It fails when a job has no stage
# tag, when a stage is unknown, when a `needs:` entry names no job, when the
# graph has a cycle, or when the release job does not wait for every job.
#
# Usage: scripts/ci_graph_check.sh [--workflow PATH]
#
# The stage tags are the evidence class of a job:
#   policy       static gate: lint, release metadata, workflow policy
#   build        produces a release artifact
#   test         hermetic test suite for one platform
#   verify       audits an uploaded artifact from one build job
#   integration  joins verified artifacts and writes the manifest
#   release      publishes the release

set -eu

workflow=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)/.github/workflows/ci.yml

while [ $# -gt 0 ]; do
  case "$1" in
    --workflow)
      [ $# -ge 2 ] || { echo "--workflow needs a path" >&2; exit 2; }
      workflow=$2
      shift 2
      ;;
    -h|--help)
      awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

[ -f "$workflow" ] || { echo "Not a file: $workflow" >&2; exit 2; }
[ -r "$workflow" ] || { echo "Not readable: $workflow" >&2; exit 2; }
command -v tr >/dev/null 2>&1 || { echo "tr is required to read the workflow" >&2; exit 2; }
command -v wc >/dev/null 2>&1 || { echo "wc is required to read the workflow" >&2; exit 2; }
command -v awk >/dev/null 2>&1 || { echo "awk is required to read the workflow" >&2; exit 2; }

# Some awk implementations end a record at a NUL byte. Count NUL bytes first.
# Read through a temporary file so a failed read cannot look like an empty
# file and a zero-byte count cannot pass as a clean scan.
nul_file=$(mktemp "${TMPDIR:-/tmp}/hs-graph-nul.XXXXXX") || {
  echo "Cannot create a temporary file to read the workflow" >&2
  exit 2
}
if ! LC_ALL=C tr -cd '\000' < "$workflow" > "$nul_file"; then
  rm -f "$nul_file"
  echo "Cannot read the workflow: $workflow" >&2
  exit 2
fi
nul_bytes=$(wc -c < "$nul_file" | tr -d ' \t\r\n')
rm -f "$nul_file"
case "$nul_bytes" in
  ''|*[!0-9]*)
    echo "Cannot count NUL bytes in the workflow: $workflow" >&2
    exit 2
    ;;
esac

LC_ALL=C awk -v workflow="$workflow" -v nul_bytes="$nul_bytes" '
function record(dep, target,   key) {
  key = dep SUBSEP target
  if (key in edge) return
  edge[key] = 1
  deps_of[target] = deps_of[target] " " dep
  children[dep] = children[dep] " " target
  indeg[target]++
  dep_seen[dep] = 1
}

function stage_known(value,   i) {
  for (i = 1; i <= 6; i++) {
    if (value == allowed[i]) return 1
  }
  return 0
}

function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function indent_of(s) { match(s, /^[ \t]*/); return RLENGTH }
function graph_note(msg) { printf "FAIL  %s\n", msg; errors++ }

BEGIN {
  inside = 0
  jobcount = 0
  pending = ""
  job = ""
  inlist = 0
  list_ind = -1
  errors = 0
  jobs_seen = 0
  top_scalar = 0
  block = -1
  plain_ind = -1
  split("policy build test verify integration release", allowed, " ")
  # The stage of every reviewed job is pinned. Moving a stage comment to a
  # different job, or adding an untagged job, fails instead of silently
  # changing the evidence class that the graph reports.
  n = split("lint:policy release-audit:policy rust-macos:build rust-windows:test rust-linux:test desktop-demo:test desktop-windows:test winui-demo:test android-demo:test ios:build macos-app:build verify-macos-binary:verify verify-ios-ipa:verify verify-macos-app:verify artifact-integrity:integration release:release", stage_pairs, " ")
  for (i = 1; i <= n; i++) {
    split(stage_pairs[i], pair, ":")
    pinned_stage[pair[1]] = pair[2]
  }
  if (nul_bytes + 0 > 0) graph_note("unsupported NUL byte in the workflow; the check reads text only")
}

{
  line = $0
  if (index(line, "\r") > 0) {
    graph_note("unsupported carriage return line break at line " NR)
    next
  }
  # YAML also reads NEL, LS, and PS as line breaks. This scanner splits on LF
  # only, so reject every byte outside printable ASCII and tab.
  if (line ~ /[^\t\040-\176]/) {
    graph_note("unsupported byte outside printable ASCII at line " NR "; YAML can read it as a line break")
    next
  }
  if (line ~ /^[ \t]*$/) next
  ind = indent_of(line)
  if (index(substr(line, 1, ind), "\t") > 0) {
    graph_note("unsupported tab indentation at line " NR)
    next
  }
  if (block >= 0) {
    if (ind > block) next
    block = -1
  }
  # A comment at column zero does not end the jobs mapping.
  if (ind == 0 && line ~ /^#/) next
  if (ind == 0) {
    # A top-level key ends the jobs mapping. A second jobs mapping is
    # ambiguous: GitHub and this check could read different jobs.
    inside = 0
    job = ""
    inlist = 0
    top_scalar = 0
    if (line ~ /^%/) {
      graph_note("unsupported YAML directive at line " NR)
      next
    }
    if (line == "---" || line == "...") {
      graph_note("unsupported YAML document marker at line " NR)
      next
    }
    if (line ~ /^#/) next
    p = index(line, ":")
    if (p == 0) {
      graph_note("unsupported top-level entry at line " NR)
      next
    }
    key = trim(substr(line, 1, p - 1))
    val = trim(substr(line, p + 1))
    quoted_key = 0
    if (key ~ /^["\047]/) {
      quoted_key = 1
      qk = substr(key, 2, length(key) - 2)
      if (length(key) < 2 || substr(key, length(key), 1) != substr(key, 1, 1)) {
        graph_note("unsupported quoted top-level key at line " NR)
        next
      }
      key = qk
    }
    lower = tolower(key)
    if (lower == "jobs" && key != "jobs") {
      graph_note("ambiguous case variant of the jobs key at line " NR)
      next
    }
    if (key == "jobs") {
      if (quoted_key) {
        graph_note("unsupported quoted jobs key at line " NR)
        next
      }
      jobs_seen++
      if (jobs_seen > 1) graph_note("duplicate jobs mapping at line " NR)
      if (val != "") {
        graph_note("unsupported inline jobs mapping at line " NR)
        next
      }
      inside = 1
      next
    }
    if (val ~ /^[|>][-+0-9]*[ \t]*$/) {
      graph_note("unsafe top-level block scalar at line " NR)
      block = 0
      next
    }
    if (val != "") top_scalar = 1
    next
  }
  # An indented comment does not continue a top-level scalar.
  if (top_scalar && line ~ /^[ \t]*#/) next
  if (top_scalar) {
    graph_note("unsafe top-level scalar continuation at line " NR)
    top_scalar = 0
    next
  }
  if (!inside) next

  if (/^  # ci-stage:/) {
    stage = $0
    sub(/^  # ci-stage:[ \t]*/, "", stage)
    sub(/[ \t]+$/, "", stage)
    pending = stage
    next
  }

  # A comment inside the jobs mapping is not a job header and does not end it.
  if (/^[ \t]*#/) next

  # A plain scalar can continue on a more indented line. GitHub reads the
  # joined value, so a scanner that reads one line can miss part of it.
  if (plain_ind >= 0) {
    if (ind > plain_ind) {
      graph_note("unsupported plain scalar continuation at line " NR)
      next
    }
    plain_ind = -1
  }

  # A merge key, anchor, alias, or tag can move a condition or a needs list
  # into a job without a line this check reads. Reject the spelling.
  node = substr($0, ind + 1)
  sub(/^-[ \t]+/, "", node)
  if (node ~ /^["\047]?<<["\047]?[ \t]*:/ || node ~ /^[&*!]/ || node ~ /:[ \t]+[&*!][^ \t=&]/) {
    graph_note("unsupported YAML merge key, anchor, alias, or tag at line " NR)
    next
  }

  if (ind == 2) {
    if ($0 ~ /^  [A-Za-z0-9_-]+:[[:space:]]*$/) {
      id = $0
      sub(/^  /, "", id)
      sub(/:[[:space:]]*$/, "", id)
      lc = tolower(id)
      if (lc in job_lc) {
        printf "FAIL  duplicate job header at line %d: %s\n", NR, id
        errors++
      } else {
        job_lc[lc] = id
      }
      jobcount++
      jobs[jobcount] = id
      stage_of[id] = pending
      pending = ""
      job = id
      inlist = 0
      next
    }
    # Reject alternate job header syntax rather than silently omitting a job
    # from the graph, or reading a line from a scalar as a job.
    printf "FAIL  unsupported job header: %s\n", $0
    errors++
    job = ""
    next
  }

  if (job != "") {
    body = $0
    sub(/^    /, "", body)
    p = index(body, ":")
    if (p > 0) {
      key = trim(substr(body, 1, p - 1))
      bare = key
      gsub(/^["\047]|["\047]$/, "", bare)
      lower = tolower(bare)
      quoted_if = (key == "\"if\"" || key == "\047if\047")
      if ((lower == "needs" || lower == "if") && bare != lower) {
        if (!(lower == "if" && quoted_if)) {
          graph_note("ambiguous case variant of the " lower " key at line " NR)
          next
        }
      }
      if (lower == "needs" && !($0 ~ /^    needs: \[/)) {
        if (!($0 ~ /^    needs:[[:space:]]*$/)) {
          graph_note("unsupported needs spelling at line " NR)
          next
        }
      }
      # A job mapping may not repeat a key. GitHub can read the last value, so
      # a second needs or steps key can hide an edge or a step from the graph.
      if (ind == 4 && bare != "") {
        jk = job SUBSEP bare
        if (jk in job_key_seen) {
          graph_note("duplicate key " bare " in job " job " at line " NR)
          next
        }
        job_key_seen[jk] = 1
        val = trim(substr(body, p + 1))
        if (val != "" && val !~ /^[|>]/ && val !~ /^["\047]/ && val !~ /^[[{]/) plain_ind = 4
      }
    }
  }

  if (job != "" && /^    needs: \[/) {
    line = $0
    sub(/^    needs: \[/, "", line)
    if (index(line, "]") == 0) {
      graph_note("unsupported multi-line flow sequence at line " NR)
      next
    }
    sub(/\].*$/, "", line)
    parts_count = split(line, parts, ",")
    for (i = 1; i <= parts_count; i++) {
      dep = parts[i]
      gsub(/^[ \t]+|[ \t]+$/, "", dep)
      if (dep != "") record(dep, job)
    }
    next
  }

  if (job != "" && /^    needs:[[:space:]]*$/) { inlist = 1; list_ind = -1; next }

  # A block sequence may sit at the key indentation (four spaces) or one
  # level deeper (six spaces). Both are valid YAML and GitHub reads the same
  # edges. Read both, reject a mixed or other indentation, and end the list
  # at the next job body key.
  if (inlist) {
    if ($0 ~ /^      - /) {
      if (list_ind == 4) {
        graph_note("mixed needs sequence indentation at line " NR)
      }
      list_ind = 6
      dep = $0
      sub(/^      - /, "", dep)
      gsub(/^[ \t]+|[ \t]+$/, "", dep)
      if (dep != "") {
        if (dep !~ /^["\047]/ && dep !~ /^[[{]/ && dep !~ /^[|>]/) plain_ind = 6
        record(dep, job)
      }
      next
    }
    if ($0 ~ /^    - /) {
      if (list_ind == 6) {
        graph_note("mixed needs sequence indentation at line " NR)
      }
      list_ind = 4
      dep = $0
      sub(/^    - /, "", dep)
      gsub(/^[ \t]+|[ \t]+$/, "", dep)
      if (dep != "") {
        if (dep !~ /^["\047]/ && dep !~ /^[[{]/ && dep !~ /^[|>]/) plain_ind = 4
        record(dep, job)
      }
      next
    }
    if ($0 ~ /^[ \t]+-[ \t]/) {
      graph_note("unsupported needs sequence indentation at line " NR)
      inlist = 0
      next
    }
    inlist = 0
  }

  if (job != "" && /^    [^[:space:]#]/) {
    quoted_if = "^    " sprintf("%c", 39) "if" sprintf("%c", 39) "[[:space:]]*:"
    if ($0 ~ /^    if[[:space:]]*:/ || $0 ~ /^    "if"[[:space:]]*:/ || $0 ~ quoted_if) {
      condition_count[job]++
      condition[job] = $0
      next
    }
  }
}

END {
  if (jobcount == 0) {
    print "FAIL  no job was found in the workflow"
    exit 1
  }

  # Every job must carry the one stage tag that this check pins for it.
  for (i = 1; i <= jobcount; i++) {
    id = jobs[i]
    if (!(id in pinned_stage)) {
      printf "FAIL  job %s has no pinned stage mapping\n", id
      errors++
    } else {
      pinned_seen[id] = 1
      if (stage_of[id] != pinned_stage[id]) {
        printf "FAIL  job %s has stage %s, expected pinned stage %s\n", id, (stage_of[id] == "" ? "<missing>" : stage_of[id]), pinned_stage[id]
        errors++
      }
    }
  }
  for (id in pinned_stage) {
    if (!(id in pinned_seen)) {
      printf "FAIL  pinned job %s is missing from the workflow\n", id
      errors++
    }
  }
  for (i = 1; i <= jobcount; i++) {
    id = jobs[i]
    if (stage_of[id] == "") {
      printf "FAIL  job %s has no \"# ci-stage:\" tag\n", id
      errors++
    } else if (!stage_known(stage_of[id])) {
      printf "FAIL  job %s has an unknown stage: %s\n", id, stage_of[id]
      errors++
    }
  }

  # The release stage must hold one job named release.
  release_jobs = 0
  for (i = 1; i <= jobcount; i++) {
    id = jobs[i]
    if (stage_of[id] == "release") {
      release_jobs++
      if (id != "release") {
        printf "FAIL  job %s is tagged release but is not named release\n", id
        errors++
      }
    }
  }
  if (release_jobs != 1) {
    printf "FAIL  expected one job tagged release, found %d\n", release_jobs
    errors++
  }

  # Every edge must name a job.
  for (dep in dep_seen) {
    if (!(dep in stage_of)) {
      printf "FAIL  a needs entry names no job: %s\n", dep
      errors++
    }
  }
  for (key in edge) {
    split(key, pair, SUBSEP)
    if (pair[1] == pair[2]) {
      printf "FAIL  job %s needs itself\n", pair[1]
      errors++
    }
  }

  # These edges protect actual artifact flow, not just the final release join.
  split("rust-macos:verify-macos-binary ios:verify-ios-ipa macos-app:verify-macos-app verify-macos-binary:artifact-integrity verify-ios-ipa:artifact-integrity verify-macos-app:artifact-integrity", required_edges, " ")
  for (i = 1; i <= 6; i++) {
    split(required_edges[i], pair, ":")
    if (!((pair[1] SUBSEP pair[2]) in edge)) {
      printf "FAIL  missing prerequisite edge: %s -> %s\n", pair[1], pair[2]
      errors++
    }
  }

  # A job-level status function can override GitHub Actions implicit
  # success() gating and let dependent work run after a failed prerequisite.
  # Dependent verification jobs have no job-level condition; release uses one
  # exact tag condition. Deliberate policy changes must update this check.
  for (i = 1; i <= jobcount; i++) {
    id = jobs[i]
    if (deps_of[id] != "") {
      if (condition_count[id] > 1) {
        printf "FAIL  job %s has multiple conditions\n", id
        errors++
      }
      if (id == "release") {
        expected = "    if: startsWith(github.ref, \047refs/tags/v\047)"
        if (condition[id] != expected) {
          printf "FAIL  job %s overrides prerequisite status gating or the tag condition\n", id
          errors++
        }
      } else if (condition[id] != "") {
        printf "FAIL  job %s has a condition that could override prerequisite status gating\n", id
        errors++
      }
    }
  }

  # Kahn topological order. It also gives the level of each job.
  head = 1
  tail = 0
  for (i = 1; i <= jobcount; i++) {
    id = jobs[i]
    if ((indeg[id] + 0) == 0) {
      tail++
      queue[tail] = id
      level_of[id] = 0
    }
  }
  processed = 0
  while (head <= tail) {
    u = queue[head]
    head++
    processed++
    kid_count = split(children[u], kids, " ")
    for (i = 1; i <= kid_count; i++) {
      kid = kids[i]
      if (kid == "") continue
      if (level_of[u] + 1 > level_of[kid]) level_of[kid] = level_of[u] + 1
      indeg[kid]--
      if (indeg[kid] == 0) {
        tail++
        queue[tail] = kid
      }
    }
  }
  if (processed < jobcount) {
    stuck = ""
    for (i = 1; i <= jobcount; i++) {
      if (indeg[jobs[i]] > 0) stuck = stuck " " jobs[i]
    }
    printf "FAIL  the graph has a cycle among:%s\n", stuck
    errors++
  }

  # The release job must wait for every job, directly or through an edge.
  if ("release" in stage_of) {
    top = 1
    stack[1] = "release"
    reachable["release"] = 1
    reached = 0
    while (top > 0) {
      u = stack[top]
      top--
      reached++
      dep_count = split(deps_of[u], ds, " ")
      for (i = 1; i <= dep_count; i++) {
        dep = ds[i]
        if (dep == "") continue
        if (!(dep in reachable)) {
          reachable[dep] = 1
          top++
          stack[top] = dep
        }
      }
    }
    if (reached < jobcount) {
      missing = ""
      for (i = 1; i <= jobcount; i++) {
        if (!(jobs[i] in reachable)) missing = missing " " jobs[i]
      }
      printf "FAIL  the release job does not wait for:%s\n", missing
      errors++
    }
  }

  # Print the graph by level.
  maxlevel = 0
  for (i = 1; i <= jobcount; i++) {
    if (level_of[jobs[i]] > maxlevel) maxlevel = level_of[jobs[i]]
  }
  print ""
  print "CI dependency graph"
  print "Tree: " workflow
  print ""
  for (level = 0; level <= maxlevel; level++) {
    if (level == 0) {
      print "level 0  no prerequisites, run in parallel"
    } else {
      printf "level %d  runs after its needs\n", level
    }
    for (i = 1; i <= jobcount; i++) {
      id = jobs[i]
      if (level_of[id] != level) continue
      needs_text = deps_of[id]
      gsub(/^[ \t]+|[ \t]+$/, "", needs_text)
      if (needs_text == "") {
        printf "  [%-11s] %s\n", stage_of[id], id
      } else {
        printf "  [%-11s] %-22s <- %s\n", stage_of[id], id, needs_text
      }
    }
    print ""
  }

  if (errors > 0) {
    printf "%d graph check(s) failed.\n", errors
    exit 1
  }
  printf "CI graph check passed: %d jobs, every job tagged, every edge names a job, no cycle, and release waits for all.\n", jobcount
}
' "$workflow"
