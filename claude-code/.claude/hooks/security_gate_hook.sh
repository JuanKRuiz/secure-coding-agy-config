#!/bin/bash
# CodeMender security gate - Claude Code PreToolUse hook for `git push`.
#
# Wired up from .claude/settings.json:
#   matcher: "Bash", if: "Bash(git push*)"
#
# Claude Code hook contract (https://code.claude.com/docs/en/hooks):
#   - stdin:  JSON with .tool_name / .tool_input.command / ...
#   - stdout: JSON with hookSpecificOutput.permissionDecision
#             "allow" | "deny", exit 0
#
# Outcome model (see threat_model.md at the repo root for the full design):
#   PASS      - scan ran, no findings.
#   ADVISORY  - scan ran, found findings below SECURITY_GATE_BLOCK_SEVERITY.
#               Push proceeds; the finding is logged and (if configured)
#               sent to SECURITY_GATE_NOTIFY_CMD so another team can pick
#               it up post-push instead of it silently going nowhere.
#   ERROR     - the scanner itself could not produce a result (missing
#               binary, auth/quota failure, unparseable output). This is
#               NEVER treated the same as "0 findings" - it blocks by
#               default (SECURITY_GATE_ALLOW_ON_ERROR=true to opt out).
#   BLOCKED   - a finding at/above the block threshold could not be
#               auto-fixed, deferred, or cleared by `cm verify`.
#   FIXED     - a blocking finding was auto-fixed, the fix was confirmed
#               by a fresh scan (not just "tests passed"), and committed.
#
# `cm verify` (exploitability check) is expensive - it is only ever
# invoked from the escalation branch (auto-fix failed, or the fix diff is
# too large to trust automatically), never on the common-case path.
#
# NOTE: stdin is consumed below to read the hook payload, so this script
# can no longer read the RED/GREEN prompts from stdin the way the original
# Antigravity script did. The interactive `read -p` calls are redirected to
# /dev/tty instead, which only works when Claude Code is attached to a real
# terminal. In headless/CI runs those prompts fail closed (empty answer),
# i.e. unresolved blocking findings deny the push rather than silently
# passing - see SECURITY_GATE_MAX_RETRIES / escalation below.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/gate_common.sh
source "$SCRIPT_DIR/lib/gate_common.sh"

INPUT=$(cat)
COMMAND=$(printf '%s\n' "$INPUT" | jq -r '.tool_input?.command? // empty' 2>/dev/null || true)

# Defense in depth: only run the gate for git push, even if the
# matcher/`if` config above ever changes.
if ! is_git_push_command "$COMMAND"; then
  allow
fi

cd "$(_gate_repo_root)" || exit 1

# Undo only what the last `cm fix` changed (gate_fix_* in
# lib/gate_common.sh): never `git checkout -- .`, which would also wipe the
# user's unrelated uncommitted work, and never delete pre-existing
# untracked files.
revert_fix() {
  gate_fix_revert || true
}

command -v cm >/dev/null 2>&1 || handle_scan_error "codemender" "the 'cm' CLI is not on PATH"

# 1. Discover modified files (compare against remote tracking or previous commit)
MODIFIED_FILES=$(git diff --name-only origin/main 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || true)
if [ -z "$MODIFIED_FILES" ]; then
  allow
fi
read_lines_into_array MODIFIED_FILES_ARR "$MODIFIED_FILES"

# 2. Run CodeMender scan on each modified file. `cm find`'s exit-code
# contract for "found something" vs. "tool error" isn't relied on here
# (unverified against real output) - only `cm report`, the actual data
# source for the decision below, is treated as authoritative for ERROR.
echo "Running CodeMender scan on changed files..." >&2
for file in "${MODIFIED_FILES_ARR[@]}"; do
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    continue
  fi
  cm find "$file" -y --bypass-warning >/dev/null 2>&1 || true
done

REPORT_ERR_FILE=$(mktemp)
if REPORT_RAW=$(cm report --format json --bypass-warning 2>"$REPORT_ERR_FILE"); then
  REPORT_EXIT=0
else
  REPORT_EXIT=$?
fi
if [ $REPORT_EXIT -ne 0 ] || ! echo "$REPORT_RAW" | jq -e . >/dev/null 2>&1; then
  ERR_DETAIL=$(tail -c 500 "$REPORT_ERR_FILE" 2>/dev/null)
  rm -f "$REPORT_ERR_FILE"
  handle_scan_error "codemender" "'cm report' failed (exit $REPORT_EXIT): ${ERR_DETAIL:-no output}"
fi
rm -f "$REPORT_ERR_FILE"

# Filter active findings to the modified files. Supports both real `cm report`
# snake_case (`file_path`, `status`) and legacy mock PascalCase (`FilePath`, `Status`),
# includes OPEN/REOPENED/VERIFIED statuses, enforces "/" path boundaries, and
# normalizes `.file_path` to the matched repo-relative path.
SCAN_RESULT=$(echo "$REPORT_RAW" | jq --arg files "$MODIFIED_FILES" '
  ($files | split("\n")) as $mod_files |
  [ .[]
    | ((.status // .Status // "OPEN") | ascii_upcase) as $st
    | select($st != "FIXED" and $st != "DISMISSED")
    | ((.file_path // .FilePath // "") | gsub("\\\\"; "/") | ltrimstr("./")) as $fp
    | [ $mod_files[] | gsub("\\\\"; "/") | ltrimstr("./") | select(. != "" and ($fp == . or ($fp | endswith("/" + .)))) ] as $matches
    | select(($matches | length) > 0)
    | .file_path = $matches[0]
  ]
' 2>/dev/null || echo '[]')
FINDINGS_COUNT=$(echo "$SCAN_RESULT" | jq 'length' 2>/dev/null || echo 0)

if [ -z "$FINDINGS_COUNT" ] || [ "$FINDINGS_COUNT" -eq 0 ]; then
  echo "No vulnerabilities found. Allowing push." >&2
  allow
fi

# 3. Split findings by severity: advisory ones never block; blocking ones
# go through the fix/escalation loop below.
WORK_DIR=$(mktemp -d)
echo "$SCAN_RESULT" | jq -c '.[]' > "$WORK_DIR/all.jsonl"
: > "$WORK_DIR/blocking.jsonl"
: > "$WORK_DIR/advisory.jsonl"
while IFS= read -r finding; do
  [ -z "$finding" ] && continue
  SEV=$(echo "$finding" | jq -r '.severity // .Severity // "UNKNOWN"')
  if is_blocking_severity "$SEV"; then
    echo "$finding" >> "$WORK_DIR/blocking.jsonl"
  else
    echo "$finding" >> "$WORK_DIR/advisory.jsonl"
  fi
done < "$WORK_DIR/all.jsonl"

ADV_COUNT=$(wc -l < "$WORK_DIR/advisory.jsonl" | tr -d ' ')
if [ "$ADV_COUNT" -gt 0 ]; then
  ADV_JSON=$(jq -s '.' "$WORK_DIR/advisory.jsonl")
  log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
  notify "ADVISORY" "$ADV_COUNT finding(s) below the $SECURITY_GATE_BLOCK_SEVERITY block threshold were pushed without blocking. Review $SECURITY_GATE_LOG." \
    "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
fi

BLOCK_COUNT=$(wc -l < "$WORK_DIR/blocking.jsonl" | tr -d ' ')
if [ "$BLOCK_COUNT" -eq 0 ]; then
  rm -rf "$WORK_DIR"
  allow
fi

echo "Detected $BLOCK_COUNT blocking-severity vulnerabilit(y/ies). Attempting automatic remediation..." >&2

# 4. Remediate & test loop (RED-GREEN) for blocking-severity findings only.
while IFS= read -r finding <&3; do
  FINDING_ID=$(echo "$finding" | jq -r '.finding_id // .FindingID // empty')
  FILE=$(echo "$finding" | jq -r '(.file_path // .FilePath // empty) | gsub("\\\\"; "/")')
  SEV=$(echo "$finding" | jq -r '.severity // .Severity // "UNKNOWN"')

  echo "Vulnerability detected: $FINDING_ID ($SEV) in $FILE" >&2
  echo "Before applying the fix, you must write a reproducing test that fails (RED)." >&2
  prompt_user _RED_ACK "Add the test and press Enter once it is verified failing..."

  RETRY_COUNT=0
  RESOLVED=false
  LARGE_DIFF=false

  while [ $RETRY_COUNT -le "$SECURITY_GATE_MAX_RETRIES" ]; do
    echo "Attempting cm fix for: $FINDING_ID (Attempt: $((RETRY_COUNT+1)))" >&2
    # Snapshot the working tree so the gate can tell exactly which files
    # `cm fix` changed: the size check, the commit and every revert below
    # are scoped to that set, never to `git add -A` / `git checkout -- .`.
    if ! gate_fix_snapshot_begin; then
      gate_fix_reset
      rm -rf "$WORK_DIR"
      deny "Security gate could not snapshot the working tree before 'cm fix' for $FINDING_ID (unmerged paths?), so it cannot scope an automated fix commit. Resolve 'git status' and retry the push."
    fi
    if ! cm fix "$FINDING_ID" -y --bypass-warning >&2; then
      echo "cm fix itself failed. Reverting and retrying." >&2
      revert_fix
      RETRY_COUNT=$((RETRY_COUNT+1))
      continue
    fi
    # Record the fix's own file set (tracked files it changed + files it
    # created) BEFORE the test command runs, so test-run artifacts
    # (__pycache__/, .pytest_cache/, coverage files) never join it.
    if ! gate_fix_snapshot_end; then
      gate_fix_reset
      rm -rf "$WORK_DIR"
      deny "Security gate could not determine which files 'cm fix' changed for $FINDING_ID; its changes are left uncommitted in the working tree. Review 'git status' before retrying the push."
    fi

    # GREEN step: run the test suite (configurable; default assumes a
    # Python unittest layout - override SECURITY_GATE_TEST_CMD otherwise).
    if ! sh -c "$SECURITY_GATE_TEST_CMD" >&2; then
      echo "Fix broke the tests. Reverting changes..." >&2
      revert_fix
      RETRY_COUNT=$((RETRY_COUNT+1))
      continue
    fi

    # Tests passing is not proof the finding is gone - re-scan (cheap;
    # NOT `cm verify`) before trusting it.
    cm find "$FILE" -y --bypass-warning >/dev/null 2>&1 || true
    STILL_OPEN=$(cm report --format json --bypass-warning 2>/dev/null \
      | jq --arg id "$FINDING_ID" '[.[] | ((.status // .Status // "OPEN") | ascii_upcase) as $st | select($st != "FIXED" and $st != "DISMISSED") | select((.finding_id // .FindingID) == $id)] | length' 2>/dev/null || echo 1)
    if [ "$STILL_OPEN" != "0" ]; then
      echo "Tests passed, but $FINDING_ID is still reported open after rescan - not trusting this fix." >&2
      revert_fix
      RETRY_COUNT=$((RETRY_COUNT+1))
      continue
    fi

    # Don't blindly auto-commit an oversized generated patch - escalate
    # for human review instead (this is where `cm verify` may get used).
    # Size = insertions + deletions over exactly the files cm fix changed,
    # new files included (a fix that only adds files is not "0 lines").
    CHANGED_LINES=$GATE_FIX_CHANGED_LINES
    if [ "$CHANGED_LINES" -gt "$SECURITY_GATE_LARGE_FIX_LINES" ]; then
      echo "Fix diff is large ($CHANGED_LINES lines in ${#GATE_FIX_FILES[@]} file(s) > $SECURITY_GATE_LARGE_FIX_LINES) - escalating for human review instead of auto-committing." >&2
      revert_fix
      LARGE_DIFF=true
      break
    fi

    # Commit only the files cm fix changed; everything else in the working
    # tree (unrelated edits, pre-existing untracked files, test artifacts,
    # the audit log) stays untouched and uncommitted.
    if gate_fix_commit "security: automated fix for $FINDING_ID ($FILE)"; then
      COMMIT_RC=0
    else
      COMMIT_RC=$?
    fi
    if [ "$COMMIT_RC" -eq 1 ]; then
      echo "cm fix confirmed the finding closed but left no working-tree changes to commit." >&2
    elif [ "$COMMIT_RC" -ne 0 ]; then
      rm -rf "$WORK_DIR"
      deny "cm fix for $FINDING_ID passed tests and rescan, but committing its files failed (see stderr). The fix is left uncommitted in: ${GATE_FIX_FILES[*]}"
    fi
    gate_fix_reset
    echo "Fix successful, verified by rescan, and committed (GREEN)!" >&2
    log_event "FIXED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
    RESOLVED=true
    break
  done

  # 5. Escalate: retries exhausted, cm fix errored out repeatedly, or the
  # fix diff was too large to auto-trust.
  if [ "$RESOLVED" != true ]; then
    REASON_HINT="auto-fix could not make tests (and a rescan) pass"
    [ "$LARGE_DIFF" = true ] && REASON_HINT="fix diff too large to auto-trust without review"
    echo "Escalating $FINDING_ID to human review ($REASON_HINT)." >&2
    echo "Select action for finding $FINDING_ID:" >&2
    echo "1) Defer/mute with justification (logged + notified; push proceeds)" >&2
    echo "2) Check exploitability via 'cm verify' (slow - only use this if you need the answer to decide)" >&2
    echo "3) Abort and fix manually (blocks push)" >&2
    prompt_user CHOICE "Enter choice [1-3]: "

    case "$CHOICE" in
      1)
        prompt_user JUSTIFICATION "Enter deferral justification: "
        [ -z "$JUSTIFICATION" ] && JUSTIFICATION="unspecified"
        revert_fix
        log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" --arg j "$JUSTIFICATION" '{findings:[$f], justification:$j}')"
        notify "ADVISORY" "Finding $FINDING_ID ($SEV) deferred by $(git config user.email 2>/dev/null || echo unknown): $JUSTIFICATION" \
          "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
        ;;
      2)
        echo "Running cm verify - this can take a while..." >&2
        if cm verify "$FINDING_ID" -y --bypass-warning >&2; then
          VERIFY_STATUS=$(cm report --format json --bypass-warning 2>/dev/null \
            | jq -r --arg id "$FINDING_ID" '[.[] | select((.finding_id // .FindingID) == $id) | (.status // .Status // "OPEN") | ascii_upcase] | first // "OPEN"' 2>/dev/null || echo "OPEN")
          if [ "$VERIFY_STATUS" = "DISMISSED" ]; then
            echo "cm verify dismissed this finding as non-exploitable - treating as advisory and proceeding." >&2
            revert_fix
            log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"cm verify found non-exploitable"}')"
          else
            revert_fix
            log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"confirmed exploitable via cm verify"}')"
            notify "BLOCKED - HELP NEEDED" "Finding $FINDING_ID confirmed exploitable by cm verify and could not be auto-fixed. Push blocked - needs help from another team." \
              "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
            rm -rf "$WORK_DIR"
            deny "Exploitable vulnerability $FINDING_ID confirmed by 'cm verify' and could not be auto-fixed. See $SECURITY_GATE_LOG - loop in security/another team for help before pushing."
          fi
        else
          echo "cm verify found this non-exploitable - treating as advisory and proceeding." >&2
          revert_fix
          log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"cm verify found non-exploitable"}')"
        fi
        ;;
      *)
        revert_fix
        log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"unresolved - no fix, deferral, or verification decision"}')"
        rm -rf "$WORK_DIR"
        deny "Unresolved finding $FINDING_ID ($SEV): no fix, deferral, or verification decision was made. See $SECURITY_GATE_LOG."
        ;;
    esac
  fi
done 3< "$WORK_DIR/blocking.jsonl"

rm -rf "$WORK_DIR"
allow
