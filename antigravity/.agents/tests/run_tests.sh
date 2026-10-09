#!/bin/bash
# Test harness for the Antigravity security gate hooks. Mirrors
# claude-code/.claude/hooks/tests/run_tests.sh, adapted for Antigravity's
# hook envelope ({"allow_tool": ...} instead of Claude Code's
# hookSpecificOutput.permissionDecision) and its lack of a stdin JSON
# payload (Antigravity's hooks.json matcher already scopes the hook to
# `git push*`, so the script itself doesn't need to detect the command).
#
# Usage: ./run_tests.sh [path-to-agents-dir]

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
MOCK_BIN="$SCRIPT_DIR/mocks"

PASS_COUNT=0
FAIL_COUNT=0

log_fail() { echo "  FAIL: $1"; }

setup_repo() {
  local dir
  dir=$(mktemp -d)
  (
    cd "$dir" || exit 1
    git init -q
    git config user.email "dev@example.com"
    git config user.name "Test Dev"
    git config core.autocrlf false
    echo "print('hello')" > README.txt
    git add README.txt
    git commit -q -m "initial"
    echo "# a file that a scanner will flag" > vuln.py
    git add vuln.py
    git commit -q -m "add vuln.py"
  )
  echo "$dir"
}

run_hook() {
  local script="$1" repo="$2" stdin_payload="${3:-}"
  local state_dir
  state_dir=$(mktemp -d)
  (
    cd "${HOOK_RUN_CWD:-$repo}" || exit 1
    PATH="$MOCK_BIN:$PATH" \
    MOCK_STATE_DIR="$state_dir" \
    MOCK_FILE="${MOCK_FILE:-vuln.py}" \
    SECURITY_GATE_STATE_DB="$repo/.codemender-test/state.db" \
    bash "$script" <<< "$stdin_payload" > "$repo/.hook_stdout" 2> "$repo/.hook_stderr"
    echo $? > "$repo/.hook_exit"
  )
  rm -rf "$state_dir"
}

decision() {
  jq -r 'if .decision == "allow" and .allow_tool == true then "allow" elif .decision == "deny" and .allow_tool == false then "deny" else "MISSING" end' \
    "$1/.hook_stdout" 2>/dev/null
}

reason() {
  jq -r '.reason // ""' "$1/.hook_stdout" 2>/dev/null
}

log_events() {
  local repo="$1"
  [ -f "$repo/.security-gate/findings-log.ndjson" ] || { echo ""; return; }
  jq -r '.event' "$repo/.security-gate/findings-log.ndjson" 2>/dev/null | tr '\n' ','
}

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
    log_fail "$desc (expected [$expected], got [$actual])"
  fi
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
    log_fail "$desc (expected to contain [$needle], got [$haystack])"
  fi
}

cleanup_repo() { rm -rf "$1"; }

# --- test cases (same coverage as the Claude Code harness + Antigravity stdin) ---

test_cm_pass_no_findings() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=clean run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: clean scan allows" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_cm_stdin_non_push_command_allows_without_scanning() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=error run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo" \
    '{"toolCall":{"name":"run_command","args":{"CommandLine":"pytest -q"}}}'
  assert_eq "cm: non-push run_command payload on stdin allows immediately" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_cm_stdin_push_command_triggers_scan() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=error run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo" \
    '{"toolCall":{"name":"run_command","args":{"CommandLine":"git push origin main"}}}'
  assert_eq "cm: git push run_command payload on stdin triggers scan" "deny" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_cm_stdin_git_flag_push_and_malformed_json() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=error run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo" \
    '{"toolCall":{"name":"run_command","args":{"CommandLine":"git -C /repo push origin main"}}}'
  assert_eq "cm: git -C /repo push triggers scan" "deny" "$(decision "$repo")"

  MOCK_CM_REPORT_MODE=error run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo" \
    '{"toolCall":"not-an-object"}'
  assert_eq "cm: malformed non-object toolCall allows without set -e crash" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_cm_error_blocks_by_default() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=error run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: scan error blocks by default" "deny" "$(decision "$repo")"
  assert_contains "cm: error reason mentions scan failure" "$(reason "$repo")" "failed to run"
  assert_contains "cm: error logged as ERROR" "$(log_events "$repo")" "ERROR"
  cleanup_repo "$repo"
}

test_cm_error_allow_on_error_true() {
  local repo; repo=$(setup_repo)
  SECURITY_GATE_ALLOW_ON_ERROR=true MOCK_CM_REPORT_MODE=error \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: scan error allows when opted in" "allow" "$(decision "$repo")"
  assert_contains "cm: error still logged even when allowed through" "$(log_events "$repo")" "ERROR"
  cleanup_repo "$repo"
}

test_cm_advisory_low_severity_does_not_block() {
  local repo; repo=$(setup_repo)
  MOCK_CM_REPORT_MODE=low run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: low-severity finding does not block" "allow" "$(decision "$repo")"
  assert_contains "cm: low-severity finding logged as ADVISORY" "$(log_events "$repo")" "ADVISORY"
  cleanup_repo "$repo"
}

test_cm_blocking_high_severity_autofix_commits() {
  local repo; repo=$(setup_repo)
  SECURITY_GATE_TEST_CMD="echo 'running test suite on stdout'" MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: high-severity finding auto-fixed allows (clean stdout JSON)" "allow" "$(decision "$repo")"
  assert_contains "cm: fix logged as FIXED" "$(log_events "$repo")" "FIXED"
  local last_msg
  last_msg=$(cd "$repo" && git log -1 --pretty=%B)
  assert_contains "cm: fix was actually committed" "$last_msg" "F1"
  cleanup_repo "$repo"
}

test_cm_legacy_pascal_schema_autofix_commits() {
  local repo; repo=$(setup_repo)
  MOCK_CM_SCHEMA=pascal SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: legacy PascalCase schema still auto-fixes and allows" "allow" "$(decision "$repo")"
  assert_contains "cm: legacy PascalCase fix logged as FIXED" "$(log_events "$repo")" "FIXED"
  cleanup_repo "$repo"
}

test_cm_other_vuln_suffix_does_not_false_match() {
  local repo; repo=$(setup_repo)
  MOCK_REPORT_FILE="other_vuln.py" MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: finding in other_vuln.py does not match modified vuln.py" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_cm_windows_backslash_path_normalizes_and_commits() {
  local repo; repo=$(setup_repo)
  (
    cd "$repo" || exit 1
    mkdir -p sub
    echo "x = 1" > sub/vuln.py
    git add sub/vuln.py
    git commit -q -m "add sub/vuln.py"
  )
  MOCK_FILE="sub/vuln.py" MOCK_REPORT_FILE='sub\\vuln.py' \
  SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: Windows backslash file_path normalizes and allows after fix" "allow" "$(decision "$repo")"
  assert_contains "cm: Windows backslash fix logged as FIXED" "$(log_events "$repo")" "FIXED"
  cleanup_repo "$repo"
}

test_cm_rescan_reopened_status_blocks_and_reverts() {
  local repo; repo=$(setup_repo)
  MOCK_CM_RESCAN_REOPENED=true SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: REOPENED status on rescan is not treated as fixed and denies" "deny" "$(decision "$repo")"
  assert_contains "cm: REOPENED rescan finding logged as BLOCKED" "$(log_events "$repo")" "BLOCKED"
  local vuln_status
  vuln_status=$(cd "$repo" && git status --porcelain -- vuln.py)
  assert_eq "cm: REOPENED rescan reverts modified vuln.py" "" "$vuln_status"
  cleanup_repo "$repo"
}

test_cm_blocking_retries_exhausted_no_tty_fails_closed() {
  local repo; repo=$(setup_repo)
  echo "uncommitted work" >> "$repo/README.txt"
  SECURITY_GATE_TEST_CMD=false MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: unfixable finding + no tty denies" "deny" "$(decision "$repo")"
  assert_contains "cm: unresolved finding logged as BLOCKED" "$(log_events "$repo")" "BLOCKED"
  assert_contains "cm: unrelated uncommitted changes in README.txt preserved on revert" "$(cat "$repo/README.txt")" "uncommitted work"
  cleanup_repo "$repo"
}

test_cm_large_fix_diff_escalates_not_autocommitted() {
  local repo; repo=$(setup_repo)
  SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high MOCK_CM_FIX_LARGE=true \
  SECURITY_GATE_LARGE_FIX_LINES=10 \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: oversized fix diff escalates + denies (no tty)" "deny" "$(decision "$repo")"
  local vuln_status
  vuln_status=$(cd "$repo" && git status --porcelain -- vuln.py)
  assert_eq "cm: no dangling uncommitted fix left in vuln.py after escalation deny" "" "$vuln_status"
  cleanup_repo "$repo"
}

test_cm_mixed_severity_fixes_blocking_logs_advisory() {
  local repo; repo=$(setup_repo)
  SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=mixed \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: mixed severities still allow after fix" "allow" "$(decision "$repo")"
  assert_contains "cm: mixed severities log FIXED" "$(log_events "$repo")" "FIXED"
  assert_contains "cm: mixed severities log ADVISORY" "$(log_events "$repo")" "ADVISORY"
  cleanup_repo "$repo"
}

test_cm_invoked_from_agents_subdir_cwd() {
  local repo; repo=$(setup_repo)
  cp -r "$AGENTS_DIR" "$repo/.agents"
  HOOK_RUN_CWD="$repo/.agents" SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$repo/.agents/security_gate_hook.sh" "$repo" \
    '{"toolCall":{"name":"run_command","args":{"CommandLine":"git push"}}}'
  assert_eq "cm: hook invoked with PWD=<repo>/.agents auto-fixes and allows" "allow" "$(decision "$repo")"
  assert_contains "cm: hook invoked from .agents logs to <repo>/.security-gate" "$(log_events "$repo")" "FIXED"
  cleanup_repo "$repo"
}

# --- fix-scoped staging: the gate commits/reverts only what cm fix changed ---

gate_commit_files() {
  (cd "$1" && git show --pretty=format: --name-only HEAD | sed '/^$/d' | sort | tr '\n' '|')
}

test_cm_fix_commit_contains_only_fix_files() {
  local repo; repo=$(setup_repo)
  echo "scratch notes, not for shipping" > "$repo/notes.txt"
  echo "uncommitted work" >> "$repo/README.txt"
  MOCK_CM_FIX_NEW_FILE="fix helper.py" MOCK_CM_FIX_NEW_LINES=3 \
  SECURITY_GATE_TEST_CMD='mkdir -p __pycache__ && echo bytecode > __pycache__/vuln.cpython-313.pyc' \
  MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: fix-files-only commit allows" "allow" "$(decision "$repo")"
  assert_eq "cm: gate commit holds exactly the files cm fix changed (new file with a space + vuln.py)" \
    "fix helper.py|vuln.py|" "$(gate_commit_files "$repo")"
  assert_eq "cm: pre-existing untracked notes.txt is not committed" \
    "?? notes.txt" "$(cd "$repo" && git status --porcelain -- notes.txt)"
  assert_eq "cm: artifact written by the gate's test command is not committed" \
    "?? __pycache__/" "$(cd "$repo" && git status --porcelain -- __pycache__)"
  assert_eq "cm: unrelated README.txt edit stays unstaged and uncommitted" \
    " M README.txt" "$(cd "$repo" && git status --porcelain -- README.txt)"
  cleanup_repo "$repo"
}

test_cm_new_file_only_large_fix_escalates() {
  local repo; repo=$(setup_repo)
  echo "scratch notes" > "$repo/notes.txt"
  local head_before; head_before=$(cd "$repo" && git rev-parse HEAD)
  MOCK_CM_FIX_ONLY_NEW=true MOCK_CM_FIX_NEW_FILE="gen/new helper.py" MOCK_CM_FIX_NEW_LINES=100 \
  SECURITY_GATE_LARGE_FIX_LINES=10 SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: new-file-only fix over LARGE_FIX_LINES escalates + denies" "deny" "$(decision "$repo")"
  assert_contains "cm: new-file-only fix size counts the new file's lines" \
    "$(cat "$repo/.hook_stderr")" "Fix diff is large (100 lines"
  assert_eq "cm: no gate commit for the oversized new-file-only fix" \
    "$head_before" "$(cd "$repo" && git rev-parse HEAD)"
  assert_eq "cm: file created by the reverted fix is removed" \
    "absent" "$([ -e "$repo/gen/new helper.py" ] && echo present || echo absent)"
  assert_eq "cm: pre-existing untracked file survives the revert" \
    "scratch notes" "$(cat "$repo/notes.txt" 2>/dev/null)"
  cleanup_repo "$repo"
}

test_cm_small_tracked_fix_still_committed() {
  local repo; repo=$(setup_repo)
  echo "staged but unrelated" > "$repo/staged.txt"
  (cd "$repo" && git add staged.txt)
  SECURITY_GATE_TEST_CMD=true MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: small tracked-file fix allows" "allow" "$(decision "$repo")"
  assert_contains "cm: small tracked-file fix logged as FIXED" "$(log_events "$repo")" "FIXED"
  assert_eq "cm: small tracked-file fix commit holds only vuln.py" "vuln.py|" "$(gate_commit_files "$repo")"
  assert_contains "cm: fixed vuln.py content is committed" "$(cd "$repo" && git show HEAD:vuln.py)" "# fixed"
  assert_eq "cm: user's staged staged.txt stays staged, not swept into the gate commit" \
    "A  staged.txt" "$(cd "$repo" && git status --porcelain -- staged.txt)"
  cleanup_repo "$repo"
}

test_cm_failed_fix_revert_keeps_prior_edits() {
  local repo; repo=$(setup_repo)
  echo "user wip line" >> "$repo/vuln.py"
  echo "scratch notes" > "$repo/notes.txt"
  MOCK_CM_FIX_NEW_FILE="new helper.py" SECURITY_GATE_TEST_CMD=false MOCK_CM_REPORT_MODE=high \
    run_hook "$AGENTS_DIR/security_gate_hook.sh" "$repo"
  assert_eq "cm: fix that breaks tests denies" "deny" "$(decision "$repo")"
  assert_eq "cm: revert restores the pre-fix content of a file with uncommitted edits" \
    "$(printf '%s\n%s' '# a file that a scanner will flag' 'user wip line')" "$(cat "$repo/vuln.py")"
  assert_eq "cm: revert removes the file cm fix created" \
    "absent" "$([ -e "$repo/new helper.py" ] && echo present || echo absent)"
  assert_eq "cm: revert keeps the pre-existing untracked file" "scratch notes" "$(cat "$repo/notes.txt" 2>/dev/null)"
  cleanup_repo "$repo"
}

test_semgrep_pass_no_findings() {
  local repo; repo=$(setup_repo)
  MOCK_SEMGREP_MODE=clean run_hook "$AGENTS_DIR/security_gate_hook_semgrep.sh" "$repo"
  assert_eq "semgrep: clean scan allows" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_semgrep_error_blocks_by_default() {
  local repo; repo=$(setup_repo)
  MOCK_SEMGREP_MODE=error run_hook "$AGENTS_DIR/security_gate_hook_semgrep.sh" "$repo"
  assert_eq "semgrep: scan error blocks by default" "deny" "$(decision "$repo")"
  assert_contains "semgrep: error logged as ERROR" "$(log_events "$repo")" "ERROR"
  cleanup_repo "$repo"
}

test_semgrep_error_allow_on_error_true() {
  local repo; repo=$(setup_repo)
  SECURITY_GATE_ALLOW_ON_ERROR=true MOCK_SEMGREP_MODE=error \
    run_hook "$AGENTS_DIR/security_gate_hook_semgrep.sh" "$repo"
  assert_eq "semgrep: scan error allows when opted in" "allow" "$(decision "$repo")"
  cleanup_repo "$repo"
}

test_semgrep_advisory_low_severity_does_not_block() {
  local repo; repo=$(setup_repo)
  MOCK_SEMGREP_MODE=low run_hook "$AGENTS_DIR/security_gate_hook_semgrep.sh" "$repo"
  assert_eq "semgrep: INFO severity does not block" "allow" "$(decision "$repo")"
  assert_contains "semgrep: INFO severity logged as ADVISORY" "$(log_events "$repo")" "ADVISORY"
  cleanup_repo "$repo"
}

test_semgrep_blocking_high_severity_denies() {
  local repo; repo=$(setup_repo)
  MOCK_SEMGREP_MODE=high run_hook "$AGENTS_DIR/security_gate_hook_semgrep.sh" "$repo"
  assert_eq "semgrep: ERROR severity blocks" "deny" "$(decision "$repo")"
  assert_contains "semgrep: deny reason includes finding detail" "$(reason "$repo")" "Rule: x"
  cleanup_repo "$repo"
}

# --- run -----------------------------------------------------------------

for t in \
  test_cm_pass_no_findings \
  test_cm_stdin_non_push_command_allows_without_scanning \
  test_cm_stdin_push_command_triggers_scan \
  test_cm_stdin_git_flag_push_and_malformed_json \
  test_cm_error_blocks_by_default \
  test_cm_error_allow_on_error_true \
  test_cm_advisory_low_severity_does_not_block \
  test_cm_blocking_high_severity_autofix_commits \
  test_cm_legacy_pascal_schema_autofix_commits \
  test_cm_other_vuln_suffix_does_not_false_match \
  test_cm_windows_backslash_path_normalizes_and_commits \
  test_cm_rescan_reopened_status_blocks_and_reverts \
  test_cm_blocking_retries_exhausted_no_tty_fails_closed \
  test_cm_large_fix_diff_escalates_not_autocommitted \
  test_cm_mixed_severity_fixes_blocking_logs_advisory \
  test_cm_invoked_from_agents_subdir_cwd \
  test_cm_fix_commit_contains_only_fix_files \
  test_cm_new_file_only_large_fix_escalates \
  test_cm_small_tracked_fix_still_committed \
  test_cm_failed_fix_revert_keeps_prior_edits \
  test_semgrep_pass_no_findings \
  test_semgrep_error_blocks_by_default \
  test_semgrep_error_allow_on_error_true \
  test_semgrep_advisory_low_severity_does_not_block \
  test_semgrep_blocking_high_severity_denies \
; do
  echo "-- $t"
  "$t"
done

echo ""
echo "$PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ]
