#!/usr/bin/env bash
# PreToolUse guard for Edit/Write: protect applied migrations. Applied migrations are
# immutable — editing one, or overwriting an existing one, diverges every database that has
# already run it. Create a NEW timestamped migration instead.
# Exits 2 with a reason on stderr to block; exits 0 otherwise.
set -euo pipefail

raw="$(cat)"

if command -v jq >/dev/null 2>&1; then
  tool="$(printf '%s' "$raw" | jq -r '.tool_name // ""')"
  path="$(printf '%s' "$raw" | jq -r '.tool_input.file_path // ""')"
else
  # Conservative fallback: cannot tell Edit from Write, so treat any migrations-path touch
  # as a block.
  tool=""
  path="$raw"
fi

reason="applied migrations are immutable - create a NEW timestamped migration instead of editing supabase/migrations/"

# Only guard files under supabase/migrations/.
case "$path" in
  *supabase/migrations/*) ;;
  *) exit 0 ;;
esac

# Edit always modifies an existing file → always block.
if [ "$tool" = "Edit" ]; then
  echo "guard-migrations: blocked - $reason" >&2
  exit 2
fi

# Write: block only when it would overwrite a migration that already exists. Check both the
# path as given (absolute, or relative to the current dir) and relative to the project dir.
if [ "$tool" = "Write" ]; then
  if [ -e "$path" ] || [ -e "${CLAUDE_PROJECT_DIR:-.}/$path" ]; then
    echo "guard-migrations: blocked - $reason" >&2
    exit 2
  fi
  exit 0
fi

# Unknown/absent tool name (jq-less fallback): be conservative and block any migrations touch.
echo "guard-migrations: blocked - $reason" >&2
exit 2
