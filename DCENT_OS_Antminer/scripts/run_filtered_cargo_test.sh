#!/usr/bin/env bash
# Run a filtered `cargo test` only after proving the filter matches ≥1 test.
#
# Why: `cargo test FILTER` exits 0 when FILTER matches zero tests. That is
# fatal for CI pins of a module or substring. Exact single tests should use
# `run_exact_cargo_test.sh` instead.
#
# Usage:
#   bash run_filtered_cargo_test.sh [cargo-test-args...] -- FILTER [harness-args...]
#
# Example:
#   bash run_filtered_cargo_test.sh -p dcentrald-hal --lib -- am2_
#   bash run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- runtime::thread_guard::tests

set -euo pipefail

if [[ $# -lt 3 ]]; then
  printf 'Usage: %s [cargo-test-args...] -- FILTER [harness-args...]\n' "$0" >&2
  exit 2
fi

sep=-1
args=("$@")
for i in "${!args[@]}"; do
  if [[ "${args[$i]}" == "--" ]]; then
    sep=$i
    break
  fi
done

if (( sep < 0 )) || (( sep + 1 >= ${#args[@]} )); then
  printf 'ERROR: require cargo args, then --, then a non-empty FILTER\n' >&2
  exit 2
fi

cargo_args=("${args[@]:0:sep}")
filter_args=("${args[@]:sep+1}")

list_output=$(cargo test "${cargo_args[@]}" "${filter_args[@]}" -- --list)
match_count=$(
  printf '%s\n' "$list_output" |
    awk '/: test$/ { count += 1 } END { print count + 0 }'
)

if (( match_count < 1 )); then
  printf 'ERROR: filter matched zero tests (plain cargo test would false-green)\n' >&2
  printf 'cargo args: %s\n' "${cargo_args[*]}" >&2
  printf 'filter: %s\n' "${filter_args[*]}" >&2
  printf '%s\n' "$list_output" >&2
  exit 1
fi

printf 'filtered cargo test: matches=%s filter=%s\n' "$match_count" "${filter_args[*]}"
cargo test "${cargo_args[@]}" "${filter_args[@]}"
