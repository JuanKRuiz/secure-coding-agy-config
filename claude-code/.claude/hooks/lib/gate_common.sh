#!/bin/bash
# Shared helpers for the Claude Code security gate hooks (CodeMender and
# Semgrep variants). Sourced, not executed directly. See threat_model.md
# at the repo root for the design this implements (PASS / ADVISORY /
# ERROR / BLOCKED outcomes, severity-based fail-open, and why `cm verify`
# is never called on the happy path).

# --- Config (override via env, or "env" in .claude/settings.json) ---
: "${SECURITY_GATE_BLOCK_SEVERITY:=HIGH}"        # findings at/above this rank block; below are advisory
: "${SECURITY_GATE_ALLOW_ON_ERROR:=false}"       # true = let the push through when the scanner itself fails to run
: "${SECURITY_GATE_LARGE_FIX_LINES:=50}"         # cm fix diffs bigger than this escalate instead of auto-committing
: "${SECURITY_GATE_MAX_RETRIES:=1}"
: "${SECURITY_GATE_TEST_CMD:=python3 -m unittest discover -s tests}"
: "${SECURITY_GATE_NOTIFY_CMD:=}"                # optional; receives a JSON event on stdin (e.g. a Slack/ticket webhook wrapper)
: "${SECURITY_GATE_STATE_DB:=$HOME/.codemender/state.db}"
: "${SECURITY_GATE_INTERACTIVE:=false}"          # true = enable interactive terminal prompts during remediation/escalation

_gate_repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

: "${SECURITY_GATE_LOG:=$(_gate_repo_root)/.security-gate/findings-log.ndjson}"

# --- Claude Code PreToolUse hook envelope ---
allow() {
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "allow"}}'
  exit 0
}

deny() {
  local reason="$1"
  jq -n --arg reason "$reason" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# prompt_user VAR_NAME PROMPT_TEXT
# Prompts only when SECURITY_GATE_INTERACTIVE=true so automated agent hooks
# and test suites never hang on /dev/tty or abort under `set -e` on EOF.
prompt_user() {
  local __var_name="$1" __prompt="$2" __ans=""
  if [ "$SECURITY_GATE_INTERACTIVE" = "true" ]; then
    if ( : </dev/tty >/dev/tty ) 2>/dev/null; then
      read -r -p "$__prompt" __ans < /dev/tty > /dev/tty 2>&1 || __ans=""
    elif [ -t 0 ]; then
      read -r -p "$__prompt" __ans || __ans=""
    else
      __ans=""
    fi
  fi
  printf -v "$__var_name" '%s' "$__ans"
}

is_git_push_command() {
  printf '%s\n' "$1" | grep -Eq '(^|[;&|[:space:]])git([[:space:]]+(-[a-zA-Z0-9._=-]+|[a-zA-Z0-9._/-]+))*[[:space:]]+push([[:space:]]|$)'
}

# --- Severity ---
# Normalizes both CodeMender-style (CRITICAL/HIGH/MEDIUM/LOW) and
# Semgrep-style (ERROR/WARNING/INFO) severities to a common 1-4 rank.
# Unrecognized severities rank as 4 (blocking) - fail-safe, not fail-open,
# for the one axis we can't verify against real tool output.
severity_rank() {
  case "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')" in
    CRITICAL) echo 4 ;;
    HIGH|ERROR) echo 3 ;;
    MEDIUM|WARNING) echo 2 ;;
    LOW|INFO) echo 1 ;;
    *) echo 4 ;;
  esac
}

is_blocking_severity() {
  [ "$(severity_rank "$1")" -ge "$(severity_rank "$SECURITY_GATE_BLOCK_SEVERITY")" ]
}

# --- Audit log ---
# log_event EVENT TOOL EXTRA_JSON
#   EVENT: PASS | ADVISORY | ERROR | BLOCKED | FIXED
#   TOOL:  codemender | semgrep
#   EXTRA_JSON: a jq object literal merged into the record (e.g. findings, reason)
# Best-effort: a logging failure must never itself block or crash the hook.
log_event() {
  local event="$1" tool="$2" extra="$3"
  # NOTE: intentionally not `extra="${3:-{}}"` - bash doesn't brace-match
  # inside a ${var:-word} default, so that idiom parses as `${3:-{}`
  # plus a stray literal `}` appended after every non-empty $3, producing
  # invalid JSON that jq would silently reject below.
  [ -z "$extra" ] && extra="{}"
  mkdir -p "$(dirname "$SECURITY_GATE_LOG")" 2>/dev/null || true
  if ! jq -n \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg event "$event" \
    --arg tool "$tool" \
    --arg actor "$(git config user.email 2>/dev/null || echo unknown)" \
    --arg commit "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
    --argjson extra "$extra" \
    '{ts:$ts, event:$event, tool:$tool, actor:$actor, commit:$commit} + $extra' \
    >> "$SECURITY_GATE_LOG" 2>/dev/null; then
    echo "(warning: failed to write audit log entry to $SECURITY_GATE_LOG - continuing anyway, a logging failure must not block or silently pass a push)" >&2
  fi
}

# notify EVENT MESSAGE EXTRA_JSON
# Always prints a loud stderr banner (so it's visible in an interactive
# session even without a notify command configured); also invokes
# SECURITY_GATE_NOTIFY_CMD with a JSON payload on stdin if set, so another
# team/channel can be looped in without depending on the developer to
# relay it themselves. A failing notify command is logged, not fatal.
notify() {
  local event="$1" message="$2" extra="$3"
  [ -z "$extra" ] && extra="{}"
  {
    echo ""
    echo "==== SECURITY GATE: $event ===="
    echo "$message"
    echo "================================"
  } >&2
  if [ -n "$SECURITY_GATE_NOTIFY_CMD" ]; then
    local payload
    payload=$(jq -n --arg event "$event" --arg message "$message" --argjson extra "$extra" \
      '{event:$event, message:$message} + $extra')
    if ! echo "$payload" | sh -c "$SECURITY_GATE_NOTIFY_CMD" >/dev/null 2>&1; then
      echo "(notify command failed - see $SECURITY_GATE_LOG for the record)" >&2
    fi
  fi
}

# handle_scan_error TOOL REASON
# The scanner itself couldn't produce a result (missing binary, auth
# failure, crash, unparseable output) - this must never be treated the
# same as "scan ran and found nothing" (see threat_model.md T1).
handle_scan_error() {
  local tool="$1" reason="$2"
  log_event "ERROR" "$tool" "$(jq -n --arg r "$reason" '{reason:$r}')"
  notify "ERROR" "Security scan ($tool) could not run: $reason" "{}"
  if [ "$SECURITY_GATE_ALLOW_ON_ERROR" = "true" ]; then
    echo "SECURITY_GATE_ALLOW_ON_ERROR=true - allowing push despite scan failure (logged above)." >&2
    allow
  fi
  deny "Security scan ($tool) failed to run: $reason
Push blocked because the gate could not confirm the code is clean (not because a vulnerability was found).
Set SECURITY_GATE_ALLOW_ON_ERROR=true to let scan failures through if that's the intended policy - not recommended by default.
See $SECURITY_GATE_LOG for the record."
}

# Read a newline-separated file list into an array without word-splitting
# on spaces (fixes a real bug in the previous `for f in $MODIFIED_FILES`
# loop - filenames with spaces silently broke it).
read_lines_into_array() {
  local __arr_name="$1" __input="$2"
  local __line
  eval "$__arr_name=()"
  while IFS= read -r __line; do
    [ -z "$__line" ] && continue
    eval "$__arr_name+=(\"\$__line\")"
  done <<< "$__input"
}

# --- Fix-scoped staging for `cm fix` (CodeMender hook) ---
# The gate must size-check, commit and revert exactly the files `cm fix`
# changed. It must never `git add -A` / `git add -u` (that sweeps in the
# user's unrelated work, artifacts written by the gate's own test run such
# as __pycache__/ or .pytest_cache/, and the audit log), and never
# `git checkout -- .` (that destroys uncommitted work).
#
# The fix set is measured from two working-tree snapshots written through
# throwaway index files (GIT_INDEX_FILE), so the real index is untouched:
#   - gate_fix_snapshot_begin, right before `cm fix`: the working-tree
#     content of every tracked file AND of every untracked, non-ignored
#     file that already exists -> GATE_FIX_PRE_TREE.
#   - gate_fix_snapshot_end, right after `cm fix` and BEFORE the test
#     command runs: the same set of paths re-read from the working tree,
#     plus every untracked file that is new since the first snapshot
#     -> GATE_FIX_POST_TREE.
# Outputs of gate_fix_snapshot_end:
#   GATE_FIX_FILES          paths that differ between the two trees: files
#                           cm fix modified or deleted (tracked or
#                           pre-existing untracked) plus files it created.
#   GATE_FIX_CHANGED_LINES  insertions + deletions over exactly those
#                           paths, new files included.
#   GATE_FIX_BINARY_FILES   fix files git diffs as binary. They cannot be
#                           reviewed by line count, so the hook escalates
#                           them as exceeding SECURITY_GATE_LARGE_FIX_LINES.
#   GATE_FIX_DIRTY_FILES    fix files whose pre-fix content already
#                           differed from HEAD (uncommitted or staged edits,
#                           or a pre-existing untracked file). Committing
#                           them would put the user's edits inside the gate
#                           commit, so the hook escalates instead.
# A revert restores every fix file to its exact pre-fix content (user
# edits included) and removes only the files cm fix created. Ignored files
# are outside the snapshot by design: they are never committed, and the
# gate does not track or revert edits to them.
GATE_FIX_PRE_TREE=""
GATE_FIX_POST_TREE=""
GATE_FIX_FILES=()
GATE_FIX_BINARY_FILES=()
GATE_FIX_DIRTY_FILES=()
GATE_FIX_CHANGED_LINES=0
_GATE_FIX_TMP=""

# _gate_fix_seed_index DEST: copy the real index to DEST (absent if the
# repo has no index yet).
_gate_fix_seed_index() {
  local real
  real=$(git rev-parse --git-path index) || return 1
  rm -f "$1"
  if [ -f "$real" ]; then
    cp "$real" "$1" || return 1
  fi
}

# _gate_fix_add_list LIST INDEX: `git add` every path in the NUL-delimited
# LIST into INDEX (literal pathspecs, spaces safe).
_gate_fix_add_list() {
  [ -s "$1" ] || return 0
  xargs -0 env GIT_INDEX_FILE="$2" GIT_LITERAL_PATHSPECS=1 git add -- \
    < "$1" > /dev/null 2>&1
}

gate_fix_reset() {
  if [ -n "$_GATE_FIX_TMP" ]; then
    rm -rf "$_GATE_FIX_TMP"
  fi
  _GATE_FIX_TMP=""
  GATE_FIX_PRE_TREE=""
  GATE_FIX_POST_TREE=""
  GATE_FIX_FILES=()
  GATE_FIX_BINARY_FILES=()
  GATE_FIX_DIRTY_FILES=()
  GATE_FIX_CHANGED_LINES=0
}

# gate_fix_snapshot_begin: call right before `cm fix`. Returns non-zero if
# the working tree could not be snapshotted (e.g. unmerged index entries).
gate_fix_snapshot_begin() {
  gate_fix_reset
  _GATE_FIX_TMP=$(mktemp -d) || return 1
  local pre="$_GATE_FIX_TMP/pre.idx" list="$_GATE_FIX_TMP/untracked.lst"
  _gate_fix_seed_index "$pre" || return 1
  GIT_INDEX_FILE="$pre" git add -u > /dev/null 2>&1 || return 1
  git ls-files -z --others --exclude-standard > "$list" || return 1
  _gate_fix_add_list "$list" "$pre" || return 1
  GATE_FIX_PRE_TREE=$(GIT_INDEX_FILE="$pre" git write-tree) || return 1
}

# gate_fix_snapshot_end: call right after `cm fix`, before anything else
# (tests, logging) writes to the working tree.
gate_fix_snapshot_end() {
  [ -n "$GATE_FIX_PRE_TREE" ] && [ -n "$_GATE_FIX_TMP" ] || return 1
  local pre="$_GATE_FIX_TMP/pre.idx" post="$_GATE_FIX_TMP/post.idx"
  local new_list="$_GATE_FIX_TMP/new.lst" head_tree f ins del path
  # Start from the pre-fix index, so pre-existing untracked files are
  # re-read by `add -u` and only genuinely new files show up as --others.
  cp "$pre" "$post" || return 1
  GIT_INDEX_FILE="$post" git add -u > /dev/null 2>&1 || return 1
  GIT_INDEX_FILE="$post" git ls-files -z --others --exclude-standard > "$new_list" || return 1
  _gate_fix_add_list "$new_list" "$post" || return 1
  GATE_FIX_POST_TREE=$(GIT_INDEX_FILE="$post" git write-tree) || return 1

  GATE_FIX_FILES=()
  while IFS= read -r -d '' f; do
    GATE_FIX_FILES+=("$f")
  done < <(git diff-tree -r -z --no-renames --name-only "$GATE_FIX_PRE_TREE" "$GATE_FIX_POST_TREE")

  GATE_FIX_CHANGED_LINES=0
  GATE_FIX_BINARY_FILES=()
  while IFS=$'\t' read -r -d '' ins del path; do
    if [ "$ins" = "-" ] || [ "$del" = "-" ]; then
      GATE_FIX_BINARY_FILES+=("$path")
      continue
    fi
    GATE_FIX_CHANGED_LINES=$((GATE_FIX_CHANGED_LINES + ins + del))
  done < <(git diff-tree -r -z --no-renames --numstat "$GATE_FIX_PRE_TREE" "$GATE_FIX_POST_TREE")

  GATE_FIX_DIRTY_FILES=()
  if [ "${#GATE_FIX_FILES[@]}" -gt 0 ]; then
    head_tree=$(git rev-parse -q --verify 'HEAD^{tree}' 2> /dev/null) \
      || head_tree=$(git hash-object -t tree /dev/null) || return 1
    while IFS= read -r -d '' f; do
      GATE_FIX_DIRTY_FILES+=("$f")
    done < <(GIT_LITERAL_PATHSPECS=1 git diff-tree -r -z --no-renames --name-only \
      "$head_tree" "$GATE_FIX_PRE_TREE" -- "${GATE_FIX_FILES[@]}")
  fi

  # The scratch indexes are no longer needed: revert/commit work from the
  # trees and GATE_FIX_FILES.
  rm -rf "$_GATE_FIX_TMP"
  _GATE_FIX_TMP=""
}

# gate_fix_revert: undo only what `cm fix` changed. Every fix file that
# existed before the fix is restored to its exact pre-fix content (through
# a scratch index, so the real index is untouched); files cm fix created
# are removed. Untouched files are left alone. Safe to call more than once,
# and a no-op if no snapshot was taken.
gate_fix_revert() {
  [ -n "$GATE_FIX_PRE_TREE" ] || return 0
  if [ -z "$GATE_FIX_POST_TREE" ] && ! gate_fix_snapshot_end; then
    echo "(warning: could not determine which files cm fix changed - working tree left as is; review 'git status')" >&2
    return 0
  fi
  [ "${#GATE_FIX_FILES[@]}" -gt 0 ] || return 0
  local f idx
  local restore=()
  for f in "${GATE_FIX_FILES[@]}"; do
    if git cat-file -e "$GATE_FIX_PRE_TREE:$f" 2> /dev/null; then
      restore+=("$f")
    else
      rm -f -- "$f"
    fi
  done
  if [ "${#restore[@]}" -gt 0 ]; then
    idx=$(mktemp) || return 0
    rm -f "$idx"
    if GIT_INDEX_FILE="$idx" git read-tree "$GATE_FIX_PRE_TREE" > /dev/null 2>&1; then
      printf '%s\0' "${restore[@]}" \
        | GIT_INDEX_FILE="$idx" git checkout-index -f -z --stdin >&2 2>&1 \
        || echo "(warning: failed to restore some files changed by cm fix - review 'git status')" >&2
    else
      echo "(warning: failed to read the pre-fix snapshot - review 'git status')" >&2
    fi
    rm -f "$idx"
  fi
}

# gate_fix_commit MESSAGE: stage and commit exactly GATE_FIX_FILES (other
# staged or unstaged changes stay where they are). The hook only calls it
# when GATE_FIX_DIRTY_FILES is empty, so the commit holds only cm fix's
# changes. Returns 0 = committed, 1 = nothing to commit, 2 = git add/commit
# failed.
gate_fix_commit() {
  local msg="$1"
  [ "${#GATE_FIX_FILES[@]}" -gt 0 ] || return 1
  GIT_LITERAL_PATHSPECS=1 git add -- "${GATE_FIX_FILES[@]}" >&2 2>&1 || return 2
  if GIT_LITERAL_PATHSPECS=1 git diff --cached --quiet HEAD -- "${GATE_FIX_FILES[@]}"; then
    return 1
  fi
  GIT_LITERAL_PATHSPECS=1 git commit -q -m "$msg" -- "${GATE_FIX_FILES[@]}" >&2 2>&1 || return 2
}
