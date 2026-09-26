#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core="$root/core/Clash.Meta"
patch_dir="$root/core/patches"
migration_dir="$patch_dir/migrations"

if [[ ! -d "$core" ]]; then
  echo "Mihomo submodule is missing: $core" >&2
  echo 'Run git submodule update --init --recursive.' >&2
  exit 1
fi

shopt -s nullglob

apply_patch() {
  local patch="$1"
  if git -C "$core" apply --check --whitespace=nowarn "$patch" >/dev/null 2>&1; then
    git -C "$core" apply --whitespace=nowarn "$patch"
    return
  fi
  if git -C "$core" apply --reverse --check --whitespace=nowarn "$patch" >/dev/null 2>&1; then
    return
  fi

  local stem legacy rollback
  stem="$(basename "${patch%.patch}")"
  for legacy in "$migration_dir"/"$stem"-*.patch; do
    if ! git -C "$core" apply --reverse --check --whitespace=nowarn "$legacy" >/dev/null 2>&1; then
      continue
    fi
    git -C "$core" apply --reverse --whitespace=nowarn "$legacy"
    if git -C "$core" apply --check --whitespace=nowarn "$patch" >/dev/null 2>&1; then
      if git -C "$core" apply --whitespace=nowarn "$patch"; then
        return
      fi
      rollback='current patch application failed'
    else
      rollback='current patch does not apply after migration'
    fi
    if ! git -C "$core" apply --whitespace=nowarn "$legacy"; then
      echo "Core patch migration rollback failed for $(basename "$legacy")." >&2
      exit 1
    fi
    echo "$rollback for $(basename "$patch")." >&2
  done

  echo "Core patch $(basename "$patch") cannot be applied, reversed, or migrated." >&2
  echo 'Reset core/Clash.Meta to the pinned submodule revision and retry.' >&2
  exit 1
}

patches=("$patch_dir"/*.patch)
for patch in "${patches[@]}"; do
  apply_patch "$patch"
done
