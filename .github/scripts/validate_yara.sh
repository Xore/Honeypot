#!/usr/bin/env bash
set -euo pipefail

rules_dir=${1:-yara-rules}
failed=0
count=0

while IFS= read -r -d '' rulefile; do
  count=$((count + 1))
  echo "Compiling $rulefile"
  if ! yara -w "$rulefile" /dev/null; then
    failed=1
  fi
done < <(
  find "$rules_dir" -type f \( -name '*.yar' -o -name '*.yara' \) \
    ! -path '*/_invalid/*' -print0
)

if [ "$count" -eq 0 ]; then
  echo "No YARA rules found below $rules_dir" >&2
  exit 1
fi

exit "$failed"
