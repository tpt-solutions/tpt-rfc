#!/usr/bin/env bash
# Copyright 2026 TPT Solutions
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Verify every Rust source file carries the dual-license SPDX header.
set -euo pipefail

missing=0
while IFS= read -r -d '' file; do
  if ! grep -q "SPDX-License-Identifier: MIT OR Apache-2.0" "$file"; then
    echo "missing license header: $file"
    missing=1
  fi
done < <(git ls-files '*.rs' | tr '\n' '\0')

if [ "$missing" -ne 0 ]; then
  echo "license header check failed"
  exit 1
fi
echo "license header check passed"
