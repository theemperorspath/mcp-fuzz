#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# mcp-fuzz.sh — MCP server endpoint discovery tool
# Uses ffuf for high-speed fuzzing across a subdomain list
# Author: built for 0dayscyber bug bounty workflow
# Usage:  ./mcp-fuzz.sh [options]
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── DEFAULTS ───────────────────────────────────────────────────
INPUT_FILE="live.txt"
WORDLIST="$(dirname "$0")/mcp-wordlist.txt"
OUTPUT_DIR="mcp-results"
THREADS=50
TIMEOUT=10
RATE=100          # requests/sec per target (be kind on bug bounty)
MATCH_CODES="200,201,301,302,307,401,403,405"
FILTER_SIZE=0     # filter empty bodies; adjust if needed
FFUF_FLAGS=""     # extra flags passed through to ffuf
PROBE_JSON=0      # also send MCP initialize probe to hits
SCHEMES="https"   # comma-sep: "https" or "https,http"
VERBOSE=0

# ─── COLOURS ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo '  ███╗   ███╗ ██████╗██████╗      ███████╗██╗   ██╗███████╗███████╗'
  echo '  ████╗ ████║██╔════╝██╔══██╗     ██╔════╝██║   ██║╚══███╔╝╚══███╔╝'
  echo '  ██╔████╔██║██║     ██████╔╝     █████╗  ██║   ██║  ███╔╝   ███╔╝ '
  echo '  ██║╚██╔╝██║██║     ██╔═══╝      ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  '
  echo '  ██║ ╚═╝ ██║╚██████╗██║          ██║     ╚██████╔╝███████╗███████╗ '
  echo '  ╚═╝     ╚═╝ ╚═════╝╚═╝          ╚═╝      ╚═════╝ ╚══════╝╚══════╝'
  echo -e "${NC}  ${YELLOW}MCP Server Discovery Tool — Bug Bounty Edition${NC}"
  echo -e "  ${YELLOW}github: theemperorspath | youtube: 0dayscyber${NC}\n"
}

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -i FILE       Input subdomain list (default: live.txt)
  -w FILE       Wordlist (default: ./mcp-wordlist.txt)
  -o DIR        Output directory (default: mcp-results)
  -t INT        ffuf threads per target (default: 50)
  -r INT        Rate limit req/sec per target (default: 100)
  -m CODES      Match HTTP codes (default: 200,201,301,302,307,401,403,405)
  -s SCHEMES    Schemes to try: https | http | https,http (default: https)
  -p            Also send MCP initialize JSON-RPC probe to confirmed hits
  -x FLAGS      Extra flags passed verbatim to ffuf
  -v            Verbose — show ffuf output in real time
  -h            This help

Examples:
  $0 -i live.txt -p
  $0 -i live.txt -s https,http -t 100 -r 200
  $0 -i live.txt -x "-H 'MCP-Protocol-Version: 2025-06-18'"
EOF
  exit 0
}

# ─── ARG PARSE ──────────────────────────────────────────────────
while getopts "i:w:o:t:r:m:s:px:vh" opt; do
  case $opt in
    i) INPUT_FILE="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    r) RATE="$OPTARG" ;;
    m) MATCH_CODES="$OPTARG" ;;
    s) SCHEMES="$OPTARG" ;;
    p) PROBE_JSON=1 ;;
    x) FFUF_FLAGS="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

banner

# ─── DEPENDENCY CHECKS ──────────────────────────────────────────
for dep in ffuf curl jq; do
  if ! command -v "$dep" &>/dev/null; then
    echo -e "${RED}[!] Missing dependency: $dep${NC}"
    [[ "$dep" == "ffuf" ]] && echo "    Install: go install github.com/ffuf/ffuf/v2@latest"
    [[ "$dep" == "jq" ]]   && echo "    Install: apt install jq / brew install jq"
    exit 1
  fi
done

[[ ! -f "$INPUT_FILE" ]] && { echo -e "${RED}[!] Input file not found: $INPUT_FILE${NC}"; exit 1; }
[[ ! -f "$WORDLIST" ]]   && { echo -e "${RED}[!] Wordlist not found: $WORDLIST${NC}"; exit 1; }

mkdir -p "$OUTPUT_DIR"/{raw,hits,probes}

HITS_MASTER="$OUTPUT_DIR/hits/all-hits.txt"
PROBE_MASTER="$OUTPUT_DIR/probes/mcp-confirmed.txt"
> "$HITS_MASTER"
> "$PROBE_MASTER"

# ─── NORMALISE SUBDOMAIN LIST ───────────────────────────────────
# Strips http:// https:// trailing slashes, blank lines, comments
NORM_FILE="$OUTPUT_DIR/.normalised_hosts"
grep -v '^#' "$INPUT_FILE" \
  | grep -v '^\s*$' \
  | sed 's|^https\?://||' \
  | sed 's|/.*||' \
  | sed 's/[[:space:]]//g' \
  | sort -u > "$NORM_FILE"

TOTAL=$(wc -l < "$NORM_FILE")
echo -e "${GREEN}[+]${NC} Loaded ${BOLD}${TOTAL}${NC} unique hosts from ${INPUT_FILE}"
echo -e "${GREEN}[+]${NC} Wordlist: ${WORDLIST} ($(wc -l < "$WORDLIST") entries)"
echo -e "${GREEN}[+]${NC} Schemes: ${SCHEMES} | Threads: ${THREADS} | Rate: ${RATE}/s"
echo -e "${GREEN}[+]${NC} Output: ${OUTPUT_DIR}\n"

# ─── MCP INITIALIZE PROBE FUNCTION ──────────────────────────────
# Sends a minimal JSON-RPC initialize request and checks for MCP indicators
probe_mcp() {
  local url="$1"
  local outfile="$2"

  local INIT_PAYLOAD='{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {},
      "clientInfo": {"name": "mcp-probe", "version": "1.0"}
    },
    "id": 1
  }'

  local response
  response=$(curl -sk \
    --max-time 10 \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: 2025-06-18" \
    -d "$INIT_PAYLOAD" \
    -w "\n---HTTP_CODE:%{http_code}---" 2>/dev/null) || return

  local http_code
  http_code=$(echo "$response" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)
  local body
  body=$(echo "$response" | sed 's/---HTTP_CODE:[0-9]*---//')

  # Check for MCP indicators in response
  local confirmed=0
  local reason=""

  if echo "$body" | grep -qiE '"protocolVersion"|"serverInfo"|"capabilities"|"jsonrpc".*"result"'; then
    confirmed=1; reason="JSON-RPC initialize response"
  elif echo "$body" | grep -qiE 'text/event-stream|data:.*jsonrpc'; then
    confirmed=1; reason="SSE stream with JSON-RPC data"
  elif echo "$body" | grep -qiE '"mcp_version"|"mcp-version"|"modelcontextprotocol"'; then
    confirmed=1; reason="MCP version field in response"
  elif echo "$body" | grep -qiE '"tools".*\[|"resources".*\[|"prompts".*\['; then
    confirmed=1; reason="MCP capability lists in response"
  elif [[ "$http_code" == "405" ]]; then
    # 405 on POST often means SSE-only endpoint (GET /sse pattern)
    confirmed=1; reason="405 Method Not Allowed (likely SSE-only endpoint)"
  fi

  if [[ $confirmed -eq 1 ]]; then
    echo -e "  ${GREEN}[MCP CONFIRMED]${NC} ${BOLD}${url}${NC} — ${reason}"
    echo "$url | $reason | HTTP:$http_code" >> "$outfile"
    echo "$url | $reason | HTTP:$http_code" >> "$PROBE_MASTER"
  else
    [[ $VERBOSE -eq 1 ]] && echo -e "  ${YELLOW}[probe]${NC} ${url} → HTTP:${http_code} (no MCP indicators)"
  fi
}

# ─── MAIN FUZZ LOOP ─────────────────────────────────────────────
count=0
IFS=',' read -ra SCHEME_LIST <<< "$SCHEMES"

while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  count=$((count + 1))

  # sanitise host — strip any leftover path components
  host=$(echo "$host" | cut -d'/' -f1)
  safe_host=$(echo "$host" | tr '.:' '__')

  echo -e "${CYAN}[${count}/${TOTAL}]${NC} ${BOLD}${host}${NC}"

  for scheme in "${SCHEME_LIST[@]}"; do
    base_url="${scheme}://${host}"
    raw_out="$OUTPUT_DIR/raw/${safe_host}_${scheme}.json"
    hits_out="$OUTPUT_DIR/hits/${safe_host}_${scheme}.txt"

    # Build ffuf command
    FFUF_CMD=(
      ffuf
      -u "${base_url}/FUZZ"
      -w "$WORDLIST"
      -t "$THREADS"
      -rate "$RATE"
      -timeout "$TIMEOUT"
      -mc "$MATCH_CODES"
      -H "User-Agent: Mozilla/5.0 (compatible; MCPScout/1.0)"
      -H "Accept: application/json, text/event-stream, */*"
      -H "MCP-Protocol-Version: 2025-06-18"
      -o "$raw_out"
      -of json
      -s               # silent (no progress bar)
    )

    # Filter by size if set
    [[ "$FILTER_SIZE" != "0" ]] && FFUF_CMD+=(-fs "$FILTER_SIZE")

    # Append extra flags if provided
    [[ -n "$FFUF_FLAGS" ]] && FFUF_CMD+=($FFUF_FLAGS)

    # Run ffuf
    if [[ $VERBOSE -eq 1 ]]; then
      "${FFUF_CMD[@]}" 2>&1 | tee /dev/stderr || true
    else
      "${FFUF_CMD[@]}" 2>/dev/null || true
    fi

    # Parse ffuf JSON output for hits
    if [[ -f "$raw_out" ]]; then
      jq -r '.results[] | "\(.status) \(.length) \(.url)"' "$raw_out" 2>/dev/null \
        | while read -r status length url; do
            echo -e "  ${GREEN}[${status}]${NC} ${url} (${length}b)"
            echo "${status} ${length} ${url}" >> "$hits_out"
            echo "${status} ${length} ${url}" >> "$HITS_MASTER"
          done

      # Count hits
      hit_count=$(jq '.results | length' "$raw_out" 2>/dev/null || echo 0)
      [[ "$hit_count" -gt 0 ]] && echo -e "  ${YELLOW}[+] ${hit_count} endpoints found${NC}"

      # Run MCP JSON-RPC probe on hits if -p flag set
      if [[ $PROBE_JSON -eq 1 && "$hit_count" -gt 0 ]]; then
        probe_out="$OUTPUT_DIR/probes/${safe_host}_${scheme}.txt"
        echo -e "  ${CYAN}[probe]${NC} Running MCP initialize probe on hits..."

        jq -r '.results[] | .url' "$raw_out" 2>/dev/null \
          | while read -r hit_url; do
              probe_mcp "$hit_url" "$probe_out"
            done
      fi
    fi

  done

done < "$NORM_FILE"

# ─── SUMMARY ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[+]${NC} Hosts scanned:  ${count}"
echo -e "${GREEN}[+]${NC} Total hits:     $(wc -l < "$HITS_MASTER" 2>/dev/null || echo 0)"
if [[ $PROBE_JSON -eq 1 ]]; then
  echo -e "${GREEN}[+]${NC} MCP confirmed:  $(wc -l < "$PROBE_MASTER" 2>/dev/null || echo 0)"
fi
echo -e "${GREEN}[+]${NC} Results dir:    ${OUTPUT_DIR}/"
echo ""

if [[ -s "$PROBE_MASTER" ]]; then
  echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━ CONFIRMED MCP SERVERS ━━━━━━━━━━━━━━${NC}"
  cat "$PROBE_MASTER"
  echo ""
elif [[ -s "$HITS_MASTER" ]]; then
  echo -e "${YELLOW}[!] Endpoints found but no MCP confirmed. Re-run with -p to probe.${NC}"
  echo -e "    Top hits:"
  head -20 "$HITS_MASTER"
fi

echo -e "${CYAN}[*]${NC} Done. Happy hunting."
