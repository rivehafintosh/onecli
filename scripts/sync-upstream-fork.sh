#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing to sync a dirty worktree." >&2
  exit 1
fi

git fetch origin --prune
git fetch upstream --prune --tags

previous_branch="$(git branch --show-current)"
git switch main
git reset --hard upstream/main

git switch dev
git merge --no-edit upstream/main

if command -v mise >/dev/null 2>&1; then
  mise exec -- pnpm install --frozen-lockfile
  mise exec -- pnpm check
else
  pnpm install --frozen-lockfile
  pnpm check
fi

git push origin main:main
git push origin dev:dev

if [[ "$previous_branch" != "dev" ]]; then
  git switch "$previous_branch"
fi
