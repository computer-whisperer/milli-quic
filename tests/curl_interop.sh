#!/usr/bin/env bash
#
# Curl interoperability tests for milli-http server examples.
#
# Usage:
#   bash tests/curl_interop.sh [--skip-h3] [--skip-build]
#
# Requires: curl (with --http2-prior-knowledge support; HTTP/3 optional)
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARY_DIR="$PROJECT_DIR/target/debug/examples"
TMP_DIR="$PROJECT_DIR/target/curl_interop"
PORT_HTTP1=8080
PORT_H2=8443
PORT_H3=4433

SKIP_H3=false
SKIP_BUILD=false

for arg in "$@"; do
    case "$arg" in
        --skip-h3)    SKIP_H3=true ;;
        --skip-build) SKIP_BUILD=true ;;
        *)            echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ── Counters ─────────────────────────────────────────────────────────────────

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# ── PID tracking ─────────────────────────────────────────────────────────────

declare -a SERVER_PIDS=()

cleanup() {
    for pid in "${SERVER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    SERVER_PIDS=()
}
trap cleanup EXIT INT TERM

# ── Helpers ──────────────────────────────────────────────────────────────────

start_server() {
    local name="$1"; shift
    local binary="$1"; shift

    mkdir -p "$TMP_DIR"
    "$binary" "$@" >"$TMP_DIR/${name}.stdout" 2>"$TMP_DIR/${name}.stderr" &
    local pid=$!
    SERVER_PIDS+=("$pid")
    echo "$pid"
}

wait_for_tcp() {
    local port="$1"
    local deadline=$((SECONDS + 10))
    while ! ss -tlnp 2>/dev/null | grep -q ":${port} "; do
        if (( SECONDS >= deadline )); then
            echo "  TIMEOUT waiting for TCP port $port"
            return 1
        fi
        sleep 0.1
    done
}

wait_for_udp() {
    local port="$1"
    local deadline=$((SECONDS + 10))
    while ! ss -ulnp 2>/dev/null | grep -q ":${port} "; do
        if (( SECONDS >= deadline )); then
            echo "  TIMEOUT waiting for UDP port $port"
            return 1
        fi
        sleep 0.1
    done
}

kill_server() {
    local pid="$1"
    kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    # Remove from tracking array
    local new=()
    for p in "${SERVER_PIDS[@]}"; do
        [[ "$p" != "$pid" ]] && new+=("$p")
    done
    SERVER_PIDS=("${new[@]+"${new[@]}"}")
}

wait_for_port_free_tcp() {
    local port="$1"
    local deadline=$((SECONDS + 5))
    while ss -tlnp 2>/dev/null | grep -q ":${port} "; do
        if (( SECONDS >= deadline )); then
            echo "  TIMEOUT waiting for TCP port $port to free"
            return 1
        fi
        sleep 0.1
    done
}

wait_for_port_free_udp() {
    local port="$1"
    local deadline=$((SECONDS + 5))
    while ss -ulnp 2>/dev/null | grep -q ":${port} "; do
        if (( SECONDS >= deadline )); then
            echo "  TIMEOUT waiting for UDP port $port to free"
            return 1
        fi
        sleep 0.1
    done
}

# run_test <name> <expected_status> <body_grep> <curl_args...>
run_test() {
    local name="$1"; shift
    local expected_status="$1"; shift
    local body_grep="$1"; shift
    # remaining args are curl arguments

    TOTAL=$((TOTAL + 1))
    echo "[test] Running: $name"

    local tmpbody="$TMP_DIR/body.tmp"
    rm -f "$tmpbody"
    local status_code
    status_code=$(curl -s --max-time 10 -o "$tmpbody" -w '%{http_code}' "$@" 2>/dev/null) || true

    local ok=true

    if [[ "$status_code" != "$expected_status" ]]; then
        echo "  FAIL: expected status $expected_status, got $status_code"
        ok=false
    fi

    if [[ -n "$body_grep" ]] && ! grep -qi "$body_grep" "$tmpbody" 2>/dev/null; then
        echo "  FAIL: body does not contain '$body_grep'"
        echo "  Body was: $(head -c 500 "$tmpbody" 2>/dev/null)"
        ok=false
    fi

    if $ok; then
        echo "  PASS: $name"
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
}

# run_test_verbose <name> <expected_status> <body_grep> <verbose_grep> <curl_args...>
run_test_verbose() {
    local name="$1"; shift
    local expected_status="$1"; shift
    local body_grep="$1"; shift
    local verbose_grep="$1"; shift

    TOTAL=$((TOTAL + 1))
    echo "[test] Running: $name"

    local tmpbody="$TMP_DIR/body.tmp"
    local tmpstderr="$TMP_DIR/stderr.tmp"
    rm -f "$tmpbody" "$tmpstderr"
    local status_code
    status_code=$(curl -v -s --max-time 10 -o "$tmpbody" -w '%{http_code}' "$@" 2>"$tmpstderr") || true

    local ok=true

    if [[ "$status_code" != "$expected_status" ]]; then
        echo "  FAIL: expected status $expected_status, got $status_code"
        ok=false
    fi

    if [[ -n "$body_grep" ]] && ! grep -qi "$body_grep" "$tmpbody" 2>/dev/null; then
        echo "  FAIL: body does not contain '$body_grep'"
        echo "  Body was: $(head -c 500 "$tmpbody" 2>/dev/null)"
        ok=false
    fi

    if [[ -n "$verbose_grep" ]] && ! grep -qi "$verbose_grep" "$tmpstderr" 2>/dev/null; then
        echo "  FAIL: verbose output does not contain '$verbose_grep'"
        echo "  Stderr was: $(head -c 1000 "$tmpstderr" 2>/dev/null)"
        ok=false
    fi

    if $ok; then
        echo "  PASS: $name"
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
}

skip_test() {
    local name="$1"
    TOTAL=$((TOTAL + 1))
    SKIPPED=$((SKIPPED + 1))
    echo "[skip] $name"
}

# Start a single-accept server, wait for port, run one test, kill it.
# Usage: single_shot_test <binary> <port> <proto> <test_func> <test_args...>
#   proto: "tcp" or "udp"
single_shot_tcp() {
    local binary="$1"; shift
    local port="$1"; shift
    local server_name="$1"; shift
    # remaining: test function + args

    local pid
    pid=$(start_server "$server_name" "$binary")
    wait_for_tcp "$port" || { kill_server "$pid"; return 1; }
    "$@"
    kill_server "$pid"
    sleep 0.2
    wait_for_port_free_tcp "$port" || true
}

single_shot_udp() {
    local binary="$1"; shift
    local port="$1"; shift
    local server_name="$1"; shift

    local pid
    pid=$(start_server "$server_name" "$binary")
    wait_for_udp "$port" || { kill_server "$pid"; return 1; }
    "$@"
    kill_server "$pid"
    sleep 0.2
    wait_for_port_free_udp "$port" || true
}

# ── Check prerequisites ─────────────────────────────────────────────────────

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl not found"
    exit 1
fi

HAS_H3=false
if curl --http3-only -V &>/dev/null 2>&1 && curl -V 2>/dev/null | grep -qi 'http3'; then
    HAS_H3=true
fi

if $SKIP_H3; then
    HAS_H3=false
fi

echo "curl version: $(curl -V 2>/dev/null | head -1)"
echo "HTTP/3 support: $HAS_H3"
echo ""

# ── Build ────────────────────────────────────────────────────────────────────

if ! $SKIP_BUILD; then
    echo "Building examples..."
    (cd "$PROJECT_DIR" && cargo build --examples --features "h3,h2,http1,rustcrypto-chacha" 2>&1)
    echo "Build complete."
    echo ""
fi

# Verify binaries exist
for bin in http1_server h2_server h3_server multi_server; do
    if [[ ! -x "$BINARY_DIR/$bin" ]]; then
        echo "ERROR: $BINARY_DIR/$bin not found or not executable"
        exit 1
    fi
done

mkdir -p "$TMP_DIR"

# ── Check ports are free ────────────────────────────────────────────────────

for port in $PORT_HTTP1 $PORT_H2 $PORT_H3; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || ss -ulnp 2>/dev/null | grep -q ":${port} "; then
        echo "ERROR: port $port is already in use"
        exit 1
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
#  Group A: HTTP/1.1 (http1_server on :8080)
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " HTTP/1.1 Tests (http1_server, port $PORT_HTTP1)"
echo "=========================================="

single_shot_tcp "$BINARY_DIR/http1_server" $PORT_HTTP1 "http1_A1" \
    run_test "A1: HTTP/1.1 basic GET" "200" "Hello from milli-http" \
    "http://127.0.0.1:${PORT_HTTP1}/"

single_shot_tcp "$BINARY_DIR/http1_server" $PORT_HTTP1 "http1_A2" \
    run_test_verbose "A2: HTTP/1.1 response headers" "200" "" "server: milli-http" \
    "http://127.0.0.1:${PORT_HTTP1}/"

single_shot_tcp "$BINARY_DIR/http1_server" $PORT_HTTP1 "http1_A3" \
    run_test "A3: HTTP/1.1 HEAD request" "200" "" \
    -I "http://127.0.0.1:${PORT_HTTP1}/"

single_shot_tcp "$BINARY_DIR/http1_server" $PORT_HTTP1 "http1_A4" \
    run_test "A4: HTTP/1.1 POST with body" "200" "Hello from milli-http" \
    -X POST -d "test=data" "http://127.0.0.1:${PORT_HTTP1}/"

single_shot_tcp "$BINARY_DIR/http1_server" $PORT_HTTP1 "http1_A5" \
    run_test "A5: HTTP/1.1 protocol marker" "200" "HTTP/1.1" \
    "http://127.0.0.1:${PORT_HTTP1}/"

echo ""

# ══════════════════════════════════════════════════════════════════════════════
#  Group B: HTTP/2 cleartext (h2_server on :8443)
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " HTTP/2 Tests (h2_server, port $PORT_H2)"
echo "=========================================="

single_shot_tcp "$BINARY_DIR/h2_server" $PORT_H2 "h2_B1" \
    run_test "B1: HTTP/2 basic GET" "200" "Hello from milli-http" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

single_shot_tcp "$BINARY_DIR/h2_server" $PORT_H2 "h2_B2" \
    run_test_verbose "B2: HTTP/2 protocol reported" "200" "" "HTTP/2" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

single_shot_tcp "$BINARY_DIR/h2_server" $PORT_H2 "h2_B3" \
    run_test_verbose "B3: HTTP/2 server header" "200" "" "server: milli-http" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

single_shot_tcp "$BINARY_DIR/h2_server" $PORT_H2 "h2_B4" \
    run_test "B4: HTTP/2 protocol marker" "200" "HTTP/2" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

single_shot_tcp "$BINARY_DIR/h2_server" $PORT_H2 "h2_B5" \
    run_test_verbose "B5: HTTP/2 content-type" "200" "" "content-type: text/html" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

echo ""

# ══════════════════════════════════════════════════════════════════════════════
#  Group C: HTTP/3 QUIC (h3_server on :4433)
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " HTTP/3 Tests (h3_server, port $PORT_H3)"
echo "=========================================="

if $HAS_H3; then
    single_shot_udp "$BINARY_DIR/h3_server" $PORT_H3 "h3_C1" \
        run_test "C1: HTTP/3 basic GET" "200" "Hello from milli-quic" \
        --http3-only -k "https://127.0.0.1:${PORT_H3}/"

    single_shot_udp "$BINARY_DIR/h3_server" $PORT_H3 "h3_C2" \
        run_test_verbose "C2: HTTP/3 protocol reported" "200" "" "HTTP/3" \
        --http3-only -k "https://127.0.0.1:${PORT_H3}/"

    single_shot_udp "$BINARY_DIR/h3_server" $PORT_H3 "h3_C3" \
        run_test "C3: HTTP/3 protocol marker" "200" "HTTP/3 (QUIC)" \
        --http3-only -k "https://127.0.0.1:${PORT_H3}/"
else
    skip_test "C1: HTTP/3 basic GET (no HTTP/3 support or --skip-h3)"
    skip_test "C2: HTTP/3 protocol reported (no HTTP/3 support or --skip-h3)"
    skip_test "C3: HTTP/3 protocol marker (no HTTP/3 support or --skip-h3)"
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
#  Group D: Multi-server (multi_server on :8443 + :4433)
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " Multi-server Tests (multi_server, port $PORT_H2 + $PORT_H3)"
echo "=========================================="

MULTI_PID=$(start_server "multi_server" "$BINARY_DIR/multi_server")
wait_for_tcp $PORT_H2 || { echo "ERROR: multi_server TCP failed to start"; kill_server "$MULTI_PID"; exit 1; }
if $HAS_H3; then
    wait_for_udp $PORT_H3 || echo "  WARNING: multi_server UDP port not ready"
fi

run_test "D1: Multi-server H2 GET" "200" "Hello from milli-http" \
    --http2-prior-knowledge "http://127.0.0.1:${PORT_H2}/"

if $HAS_H3; then
    run_test "D2: Multi-server H3 GET" "200" "Hello from milli-http" \
        --http3-only -k "https://127.0.0.1:${PORT_H3}/"
else
    skip_test "D2: Multi-server H3 GET (no HTTP/3 support or --skip-h3)"
fi

kill_server "$MULTI_PID"

echo ""

# ══════════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " Test Summary"
echo "=========================================="
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "=========================================="

if (( FAILED > 0 )); then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
