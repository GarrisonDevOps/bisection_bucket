#!/usr/bin/env bash
# PostToolUse hook: validate a just-edited file against this repo's pre-commit rules.
#
# Runs `pre-commit run --files <file>` on the file that Edit/Write/MultiEdit
# touched. On failure it prints the output to stderr and exits 2, which feeds the
# result back to Claude so it can fix the issue. A clean run exits 0 silently.
set -euo pipefail
IFS=$'\n\t'

# no-commit-to-branch guards the branch, not file content, and would fire
# spuriously (e.g. on jj's detached HEAD). It is irrelevant to file validation.
export SKIP="no-commit-to-branch"

# Run through `mise exec` so mise-managed tools that the hooks rely on
# (pre-commit, jsonnet-tool, shfmt, ...) are on PATH, matching a normal
# interactive shell.
if ! command -v mise >/dev/null 2>&1; then
  echo "pre-commit validation hook requires mise to run." >&2
  exit 1
fi

run() { mise exec -- "$@"; }

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0

input="$(cat)"
file="$(printf '%s' "$input" | mise exec jq@1.8 -- jq -r '.tool_input.file_path // empty')"
[[ -z $file ]] && exit 0

# Only validate files that live inside this repository.
case "$file" in
"$repo_root"/*) ;;
*) exit 0 ;;
esac

if ! output="$(cd "$repo_root" && run pre-commit run --files "$file" 2>&1)"; then
  {
    echo "pre-commit reported issues on ${file#"$repo_root"/}:"
    echo
    echo "$output"
    echo
    echo "Re-read the file (hooks such as trailing-whitespace, shfmt, and"
    echo "generate may have rewritten it) and fix any remaining problems."
  } >&2
  exit 2
fi

exit 0
