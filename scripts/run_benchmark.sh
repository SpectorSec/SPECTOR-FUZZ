#!/usr/bin/env bash
set -euo pipefail

# Benchmark runner for SpecterFuzz against DeFiHackLabs dataset.
# Usage: ./run_benchmark.sh [--manifest manifest.json] [--timeout 300] [--filter NAME]
#        ./run_benchmark.sh --list                     # list available targets
#        ./run_benchmark.sh --run BarleyFinance        # run single target

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPTS_DIR/.."
MANIFEST="${SCRIPTS_DIR}/benchmark_manifest.json"
TIMEOUT=300  # seconds per target
ANVIL_PORT=8545
ANVIL_HOST="127.0.0.1"
FUZZER_BIN="cargo run --manifest-path $PROJECT_DIR/Cargo.toml --release --"
FUZZER_FLAGS="-f --concolic --sha3-bypass -d all --run-forever"
ETHERSCAN_KEY="${ETHERSCAN_KEY:-F2Y8KBJ66MHHPJ2IGT94IIUW4SD7KJKXBQ}"
RESULTS_DIR="$SCRIPTS_DIR/benchmark_results"
SKIP_EXISTING=1

# RPC endpoints (override via env: export ETH_RPC=..., BSC_RPC=..., etc.)
declare -A RPCS
RPCS["eth"]="${ETH_RPC:-https://eth.merkle.io}"
RPCS["bsc"]="${BSC_RPC:-https://binance.llamarpc.com}"
RPCS["arbitrum"]="${ARBITRUM_RPC:-https://arb1.arbitrum.io/rpc}"
RPCS["polygon"]="${POLYGON_RPC:-https://rpc.ankr.com/polygon}"
RPCS["avalanche"]="${AVALANCHE_RPC:-https://avax.meowrpc.com}"
RPCS["fantom"]="${FANTOM_RPC:-https://rpc.fantom.network}"
RPCS["optimism"]="${OPTIMISM_RPC:-https://optimism.llamarpc.com}"
RPCS["base"]="${BASE_RPC:-https://developer-access-mainnet.base.org}"
RPCS["celo"]="${CELO_RPC:-https://rpc.ankr.com/celo}"
RPCS["gnosis"]="${GNOSIS_RPC:-https://gnosis-mainnet.public.blastapi.io}"
RPCS["linea"]="${LINEA_RPC:-https://linea.drpc.org}"
RPCS["mantle"]="${MANTLE_RPC:-https://rpc.mantle.xyz}"
RPCS["blast"]="${BLAST_RPC:-https://rpc.ankr.com/blast}"
RPCS["moonriver"]="${MOONRIVER_RPC:-https://moonriver.public.blastapi.io}"
RPCS["sei"]="${SEI_RPC:-https://sei.drpc.org}"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --manifest FILE    JSON manifest of targets (default: $MANIFEST)
  --timeout SECS     Max seconds per target (default: $TIMEOUT)
  --filter PATTERN   Only run targets whose name matches this grep pattern
  --run NAME         Run a single target by name
  --list             List available targets
  --force            Re-run targets even if results exist
  --etherscan-key KEY Override Etherscan API key
EOF
    exit 0
}

# Parse args
FILTER=""
RUN_SINGLE=""
LIST_ONLY=0
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --filter) FILTER="$2"; shift 2 ;;
        --run) RUN_SINGLE="$2"; shift 2 ;;
        --list) LIST_ONLY=1; shift ;;
        --force) FORCE=1; shift ;;
        --help|-h) usage ;;
        *) echo "Unknown arg: $1"; usage ;;
    esac
done

if [ ! -f "$MANIFEST" ]; then
    echo "Generating manifest..."
    python3 "$SCRIPTS_DIR/extract_targets.py"
fi

if [ "$LIST_ONLY" = 1 ]; then
    echo "Available targets:"
    jq -r '.[] | "\(.name)  \(.chain)  block=\(.block)  addrs=\(.addresses|length)"' "$MANIFEST"
    exit 0
fi

mkdir -p "$RESULTS_DIR"

# Build once up front
echo "Building SpecterFuzz..."
cargo build --manifest-path "$PROJECT_DIR/Cargo.toml" --release 2>&1 | tail -5

# Select targets
SELECT_CMD=".[]"
if [ -n "$FILTER" ]; then
    SELECT_CMD=".[] | select(.name | test(\"$FILTER\"))"
fi

targets=$(jq -c "$SELECT_CMD" "$MANIFEST")
target_count=$(echo "$targets" | jq -s 'length')

echo "Running $target_count targets (timeout=${TIMEOUT}s each)..."

echo "$targets" | while read -r target; do
    name=$(echo "$target" | jq -r '.name')
    chain=$(echo "$target" | jq -r '.chain')
    chain_id=$(echo "$target" | jq -r '.chain_id')
    block=$(echo "$target" | jq -r '.block')
    explorer=$(echo "$target" | jq -r '.explorer')
    addresses=$(echo "$target" | jq -r '.addresses | join(",")')

    result_dir="$RESULTS_DIR/$name"
    result_file="$result_dir/result.json"

    if [ -f "$result_file" ] && [ "$FORCE" = 0 ] && [ -z "$RUN_SINGLE" ]; then
        echo "  [skip] $name — results exist"
        continue
    fi
    if [ -n "$RUN_SINGLE" ] && [ "$name" != "$RUN_SINGLE" ]; then
        continue
    fi

    echo ""
    echo "========================================"
    echo "  Target: $name"
    echo "  Chain:  $chain (id=$chain_id)"
    echo "  Block:  $block"
    echo "  Addrs:  $(echo "$target" | jq -r '.addresses | length')"
    echo "========================================"
    echo ""

    mkdir -p "$result_dir"
    rpc_url="${RPCS[$chain]:-}"
    if [ -z "$rpc_url" ]; then
        echo "  [skip] $name — no RPC URL for chain $chain"
        continue
    fi

    # Start anvil fork
    anvil --fork-url "$rpc_url" \
          --fork-block-number "$block" \
          --host "$ANVIL_HOST" \
          --port "$ANVIL_PORT" \
          --silent &
    ANVIL_PID=$!
    echo "  anvil PID=$ANVIL_PID"

    # Wait for anvil to be ready
    for i in $(seq 1 30); do
        if curl -sf -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            "http://$ANVIL_HOST:$ANVIL_PORT" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Run fuzzer with timeout
    echo "  Running fuzzer (${TIMEOUT}s)..."
    fuzzer_cmd="$FUZZER_BIN $FUZZER_FLAGS -u http://$ANVIL_HOST:$ANVIL_PORT -i $chain_id -e \"$explorer\" -n $chain -t $addresses"
    echo "  $fuzzer_cmd"

    START_TS=$(date +%s)
    export ETHERSCAN_API_KEY="$ETHERSCAN_KEY"
    # Run fuzzer with timeout; capture exit code and output
    cd "$PROJECT_DIR"
    timeout "$TIMEOUT" bash -c "$fuzzer_cmd" 2>&1 | tee "$result_dir/fuzzer.log" || true
    FUZZER_EXIT=$?
    END_TS=$(date +%s)
    DURATION=$((END_TS - START_TS))

    # Kill anvil
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true

    # Check for success indicators in output
    SUCCESS=0
    if grep -qiE "(exploit|vuln|bug found|critical|reentrancy|detected)" "$result_dir/fuzzer.log" 2>/dev/null; then
        SUCCESS=1
    fi

    cat > "$result_file" <<EOF
{
  "name": "$name",
  "chain": "$chain",
  "block": $block,
  "duration_secs": $DURATION,
  "exit_code": $FUZZER_EXIT,
  "success": $SUCCESS,
  "addresses": [$(echo "$addresses" | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')]
}
EOF

    echo "  Done: $name (${DURATION}s, exit=$FUZZER_EXIT, success=$SUCCESS)"
done

echo ""
echo "Benchmark complete."
echo "Results in: $RESULTS_DIR"
echo ""
echo "Summary:"
for d in "$RESULTS_DIR"/*/; do
    if [ -f "$d/result.json" ]; then
        jq -r '"\(.name): \(.duration_secs)s success=\(.success)"' "$d/result.json"
    fi
done
