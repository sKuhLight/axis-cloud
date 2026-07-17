#!/usr/bin/env bash
# PreToolUse guard for Bash: block destructive commands, remote-mutating Supabase
# operations, and in-place writes onto applied migrations.
# Exits 2 with a one-line reason on stderr to block; exits 0 otherwise.
set -euo pipefail

raw="$(cat)"

if command -v jq >/dev/null 2>&1; then
  cmd="$(printf '%s' "$raw" | jq -r '.tool_input.command // ""')"
else
  # Conservative fallback: scan the whole raw payload.
  cmd="$raw"
fi

block() { echo "guard-bash: blocked - $1" >&2; exit 2; }

# rm -rf targeting / or ~ (root or home)
if printf '%s' "$cmd" | grep -Eq 'rm[[:space:]]+(-[A-Za-z]*[[:space:]]+)*-?[A-Za-z]*[rR][A-Za-z]*f|rm[[:space:]]+-[A-Za-z]*f[A-Za-z]*[rR]'; then
  if printf '%s' "$cmd" | grep -Eq 'rm[[:space:]]+.*[[:space:]](/|~|\$HOME)([[:space:]]|/|$)'; then
    block "rm -rf targeting / or home"
  fi
fi

# git force push (--force, --force-with-lease, or short -f flag)
if printf '%s' "$cmd" | grep -Eq 'git[[:space:]]+push' \
   && printf '%s' "$cmd" | grep -Eq '(--force([[:space:]=]|$)|[[:space:]]-[A-Za-z]*f[A-Za-z]*([[:space:]]|$))'; then
  block "git push --force is not allowed"
fi

# Remote-mutating Supabase operations — also when invoked via `npx [--yes|-y] supabase[@ver]`
# or an absolute/relative path. These change a linked/hosted project or its secrets and must
# never run unattended; deploy manually.
sb='(^|[[:space:]]|/)(npx[[:space:]]+((--yes|-y)[[:space:]]+)?)?supabase(@[^[:space:]]*)?[[:space:]]+'
if printf '%s' "$cmd" | grep -Eq "${sb}db[[:space:]]+push"; then
  block "supabase db push mutates the linked project - deploy manually"
fi
if printf '%s' "$cmd" | grep -Eq "${sb}functions[[:space:]]+deploy"; then
  block "supabase functions deploy mutates the linked project - deploy manually"
fi
if printf '%s' "$cmd" | grep -Eq "${sb}secrets[[:space:]]+set"; then
  block "supabase secrets set mutates project secrets - do this manually"
fi
if printf '%s' "$cmd" | grep -Eq "${sb}db[[:space:]]+reset[^|]*--linked"; then
  block "supabase db reset --linked wipes the linked project - never automate"
fi
if printf '%s' "$cmd" | grep -Eq "${sb}link([[:space:]]|$)"; then
  block "supabase link changes the linked project target - do this manually"
fi

# In-place writes onto applied migrations (sed -i, tee, >, >>). Migrations are immutable —
# create a NEW timestamped migration instead of rewriting an existing one.
mig='supabase/migrations/[^[:space:]]*\.sql'
if printf '%s' "$cmd" | grep -Eq "(sed[[:space:]]+-i|tee)[^|]*$mig"; then
  block "in-place write to a migration - applied migrations are immutable, create a NEW timestamped migration"
fi
if printf '%s' "$cmd" | grep -Eq '(>>?)[[:space:]]*[^|&>]*'"$mig"; then
  block "redirect onto a migration - applied migrations are immutable, create a NEW timestamped migration"
fi

exit 0
