#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/run_wt_dg_matrix.sh [options]

Run WebTransport datagram queue policy matrix against http_server -B.

Options:
  -s host:port   Server address for baton_client and http_server bind
                 (default: localhost:12347)
  -c certspec    TLS cert spec for http_server -c
                 (default: localhost,server.crt,server.key)
  -l level       Log level for server/client (default: info)
  -b value       Initial baton value for client (default: 1)
  -u list        Datagram burst values (comma-separated, default: 1,64,80,160)
  -p list        Policies (comma-separated, default: fail,oldest,newest)
  -t sec         Per-client timeout in seconds (default: 12)
  -o dir         Output directory (default: /tmp/wt_dg_matrix_<timestamp>)
  -h             Show this help

Examples:
  tools/run_wt_dg_matrix.sh
  tools/run_wt_dg_matrix.sh -u 64,80,160 -p fail,newest -o /tmp/wt-matrix
EOF
}

count_pattern() {
    local pattern="$1"
    local file="$2"

    if command -v rg >/dev/null 2>&1; then
        rg -c -- "$pattern" "$file" || true
    else
        grep -c -- "$pattern" "$file" || true
    fi
}

parse_csv() {
    local csv="$1"
    local -n out_arr=$2
    local item

    out_arr=()
    IFS=',' read -r -a out_arr <<< "$csv"
    for item in "${out_arr[@]}"; do
        if [[ -z "$item" ]]; then
            echo "empty value in list: $csv" >&2
            exit 1
        fi
    done
}

server_addr="localhost:12347"
cert_spec="localhost,server.crt,server.key"
log_level="info"
baton_value="1"
u_csv="1,64,80,160"
p_csv="fail,oldest,newest"
timeout_sec="12"
out_dir="/tmp/wt_dg_matrix_$(date +%Y%m%d_%H%M%S)"

while getopts ":s:c:l:b:u:p:t:o:h" opt; do
    case "$opt" in
    s) server_addr="$OPTARG" ;;
    c) cert_spec="$OPTARG" ;;
    l) log_level="$OPTARG" ;;
    b) baton_value="$OPTARG" ;;
    u) u_csv="$OPTARG" ;;
    p) p_csv="$OPTARG" ;;
    t) timeout_sec="$OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    h)
        usage
        exit 0
        ;;
    :)
        echo "missing argument for -$OPTARG" >&2
        usage
        exit 1
        ;;
    \?)
        echo "unknown option: -$OPTARG" >&2
        usage
        exit 1
        ;;
    esac
done

parse_csv "$u_csv" u_values
parse_csv "$p_csv" policies

mkdir -p "$out_dir"
server_log="$out_dir/server.log"
summary_file="$out_dir/summary.tsv"

cleanup() {
    if [[ -n "${srv_pid:-}" ]]; then
        kill "$srv_pid" 2>/dev/null || true
        wait "$srv_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

./bin/http_server -c "$cert_spec" -s "$server_addr" -B -L "$log_level" \
    >"$server_log" 2>&1 &
srv_pid=$!

sleep 1
if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "http_server failed to start; see $server_log" >&2
    exit 1
fi

printf "U\tpolicy\trc\tconnect_ok\tconnect_fail\tsent\tfailed\tdrop_old\tdrop_new\tq_full\n" \
    >"$summary_file"
printf "%-4s %-7s %-3s %-10s %-12s %-6s %-7s %-8s %-8s %-6s\n" \
    "U" "POLICY" "RC" "CONNECT_OK" "CONNECT_FAIL" "SENT" "FAILED" \
    "DROP_OLD" "DROP_NEW" "Q_FULL"

for u in "${u_values[@]}"; do
    for p in "${policies[@]}"; do
        case "$p" in
        fail|oldest|newest) ;;
        *)
            echo "invalid policy: $p (expected fail|oldest|newest)" >&2
            exit 1
            ;;
        esac

        client_log="$out_dir/client_U${u}_${p}.log"
        if timeout "$timeout_sec" ./bin/baton_client -s "$server_addr" \
            -L "$log_level" -b "$baton_value" -U "$u" -M "$p" \
            >"$client_log" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        connect_ok="$(count_pattern "client received successful CONNECT response" "$client_log")"
        connect_fail="$(count_pattern "CONNECT failed" "$client_log")"
        drop_old="$(count_pattern "drop queued WT datagram" "$client_log")"
        drop_new="$(count_pattern "drop newest WT datagram" "$client_log")"
        q_full="$(count_pattern "WT datagram queue full" "$client_log")"

        sent="-"
        failed="-"
        if burst_line="$(grep -m1 'burst datagram send complete' "$client_log" 2>/dev/null)"; then
            sent="$(printf "%s\n" "$burst_line" \
                | sed -n 's/.*sent=\([0-9][0-9]*\).*/\1/p')"
            failed="$(printf "%s\n" "$burst_line" \
                | sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p')"
            [[ -n "$sent" ]] || sent="-"
            [[ -n "$failed" ]] || failed="-"
        fi

        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$u" "$p" "$rc" "$connect_ok" "$connect_fail" "$sent" "$failed" \
            "$drop_old" "$drop_new" "$q_full" >>"$summary_file"
        printf "%-4s %-7s %-3s %-10s %-12s %-6s %-7s %-8s %-8s %-6s\n" \
            "$u" "$p" "$rc" "$connect_ok" "$connect_fail" "$sent" "$failed" \
            "$drop_old" "$drop_new" "$q_full"
    done
done

echo
echo "Wrote summary: $summary_file"
echo "Server log:     $server_log"
echo "Client logs:    $out_dir/client_U*_*.log"

