#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core="$root/core/Clash.Meta"
patch_dir="$root/core/patches"

if [[ ! -d "$core" ]]; then
  echo "Mihomo submodule is missing: $core" >&2
  echo 'Run git submodule update --init --recursive.' >&2
  exit 1
fi

shopt -s nullglob
patches=("$patch_dir"/*.patch)
for patch in "${patches[@]}"; do
  if git -C "$core" apply --check --whitespace=nowarn "$patch" >/dev/null 2>&1; then
    git -C "$core" apply --whitespace=nowarn "$patch"
  elif git -C "$core" apply --reverse --check --whitespace=nowarn "$patch" >/dev/null 2>&1; then
    : # already applied
  else
    echo "Core patch $(basename "$patch") cannot be applied or reversed." >&2
    echo 'Reset core/Clash.Meta to the pinned submodule revision and retry.' >&2
    exit 1
  fi
done
