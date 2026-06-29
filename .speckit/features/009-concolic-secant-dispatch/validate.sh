#!/usr/bin/env bash
# Feature 009 — concolic/secant dispatch: §7 VALIDATION HARNESS.
#
# Proves the two things that gate enabling the feature:
#   (1) NO REGRESSION  — bugs found with the dispatch ON >= baseline OFF.
#   (2) THE RATIO       — what fraction of concolic-eligible inputs were routed to
#                         the secant (the real concolic-budget win; replaces the
#                         assumed 80/20).
#
# It builds BOTH configs to separate target dirs (so neither rebuild thrashes the
# other), runs each on the SAME target for the SAME wall-clock budget with
# --concolic --run-forever, then compares bug counts and prints the ratio.
#
# USAGE:
#   TARGET='-t build/*'                       DURATION=600 ./validate.sh      # offchain
#   TARGET='-t 0xADDR -c bsc -b 123 -u $RPC -k $KEY --fetch-tx-data' \
#                                             DURATION=900 ./validate.sh      # onchain
#
# Notes:
#   * 009 only matters with --concolic (the harness forces it).
#   * Fuzzing is stochastic — one short run is noisy. Use DURATION>=600 and/or run
#     several targets; treat (1) as "ON >= OFF across the set", not a single run.
#   * Bug count = lines in <workdir>/vuln_info.jsonl. Counting is identical for ON
#     and OFF, so the COMPARISON is fair even if absolute counts double-count a
#     re-found bug under --run-forever.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO"
: "${TARGET:?set TARGET, e.g. TARGET='-t build/*'}"
: "${DURATION:=600}"                       # seconds per run
ORACLES="${ORACLES:--d all -f}"            # oracle set; -f = fund-loss
EXTRA="${EXTRA:-}"                          # any extra ityfuzz flags
OUT="${OUT:-/tmp/009-validate}"
mkdir -p "$OUT"

BASE_TD="$OUT/td-baseline"                  # separate cargo target dirs => both binaries cached
DISP_TD="$OUT/td-dispatch"

echo "== building BASELINE (feature OFF) =="
CARGO_TARGET_DIR="$BASE_TD" cargo build --release --locked 2>&1 | tail -2
BASE_BIN="$BASE_TD/release/spectorfuzz"

echo "== building DISPATCH (feature ON) =="
CARGO_TARGET_DIR="$DISP_TD" cargo build --release --locked --features concolic_secant_dispatch 2>&1 | tail -2
DISP_BIN="$DISP_TD/release/spectorfuzz"

[ -x "$BASE_BIN" ] && [ -x "$DISP_BIN" ] || { echo "BUILD FAILED"; exit 1; }

run() {
  local bin="$1" wd="$2" label="$3"
  rm -rf "$wd"; mkdir -p "$wd"
  echo "== running $label for ${DURATION}s =="
  # --run-forever so it keeps finding; timeout bounds the wall clock.
  ITYFUZZ_WORKDIR="$wd" timeout "${DURATION}s" \
    "$bin" evm $TARGET $ORACLES --concolic --run-forever --work-dir "$wd" $EXTRA \
    > "$wd/run.log" 2>&1
  local bugs=0
  [ -f "$wd/vuln_info.jsonl" ] && bugs=$(wc -l < "$wd/vuln_info.jsonl")
  echo "$label: bugs=$bugs  (log: $wd/run.log)"
  echo "$bugs"
}

OFF_BUGS=$(run "$BASE_BIN" "$OUT/wd-off" "BASELINE(OFF)" | tail -1)
ON_BUGS=$(run "$DISP_BIN" "$OUT/wd-on" "DISPATCH(ON)" | tail -1)

echo
echo "================ 009 VALIDATION RESULT ================"
echo "baseline(OFF) bugs : $OFF_BUGS"
echo "dispatch(ON)  bugs : $ON_BUGS"
echo "--- dispatch ratio (from ON run stdout) ---"
grep "\[009-dispatch\]" "$OUT/wd-on/run.log" | tail -1 || echo "  (no [009-dispatch] line — no concolic-eligible inputs hit; widen target/duration)"
echo "------------------------------------------------------"
if [ "$ON_BUGS" -ge "$OFF_BUGS" ]; then
  echo "PASS (1) no-regression: ON ($ON_BUGS) >= OFF ($OFF_BUGS)"
else
  echo "FAIL (1) REGRESSION: ON ($ON_BUGS) < OFF ($OFF_BUGS) — do NOT enable; investigate"
  echo "        likely the 'secant never engages' residual (009 spec §Implementation status)."
fi
echo "Enable the feature only after PASS across a representative target set."
