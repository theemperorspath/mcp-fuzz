<div align="center">

```
███╗   ███╗ ██████╗██████╗       ███████╗██╗   ██╗███████╗███████╗
████╗ ████║██╔════╝██╔══██╗      ██╔════╝██║   ██║╚══███╔╝╚══███╔╝
██╔████╔██║██║     ██████╔╝█████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ 
██║╚██╔╝██║██║     ██╔═══╝ ╚════╝██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
██║ ╚═╝ ██║╚██████╗██║           ██║     ╚██████╔╝███████╗███████╗ 
╚═╝     ╚═╝ ╚═════╝╚═╝           ╚═╝      ╚═════╝ ╚══════╝╚══════╝
```

**MCP Server Discovery Tool**

*Automated endpoint fuzzing and JSON-RPC confirmation for bug bounty recon*

<br>

![Shell](https://img.shields.io/badge/shell-bash-1a1a2e?style=flat-square&logo=gnubash&logoColor=white&labelColor=0d0d1a)
![Tool](https://img.shields.io/badge/powered_by-ffuf-1a1a2e?style=flat-square&labelColor=0d0d1a&color=4a9eff)
![Protocol](https://img.shields.io/badge/protocol-MCP_2025--06--18-1a1a2e?style=flat-square&labelColor=0d0d1a&color=4a9eff)
![License](https://img.shields.io/badge/license-MIT-1a1a2e?style=flat-square&labelColor=0d0d1a&color=4a9eff)

</div>

---

## Overview

MCP-Fuzz is a purpose-built reconnaissance tool for discovering **Model Context Protocol** server endpoints across large attack surfaces. It combines high-speed wordlist fuzzing via [ffuf](https://github.com/ffuf/ffuf) with an active JSON-RPC 2.0 confirmation probe — distinguishing genuine MCP servers from false positives at scale.

Built for bug bounty research. MCP adoption is accelerating rapidly across enterprise and SaaS targets; most organisations have no documented attack surface for these endpoints.

**What it finds:**

- `.well-known/` discovery manifests (SEP-1649, SEP-1960, IETF draft)
- Streamable HTTP transport endpoints (`/mcp`, `/api/mcp`, versioned paths)
- Legacy SSE transport endpoints (`/sse`, `/mcp/messages`)
- OAuth/auth metadata endpoints required by the MCP auth spec
- MCP server cards, capability advertisements, and health probes
- Framework-default paths (FastMCP, Spring AI, Node SDK, FastAPI)

---

## Requirements

| Dependency | Install |
|:-----------|:--------|
| `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| `curl` | pre-installed on most systems |
| `jq` | `apt install jq` / `brew install jq` |

---

## Quickstart

```bash
git clone https://github.com/theemperorspath/mcp-fuzz
cd mcp-fuzz
chmod +x mcp-fuzz.sh
```

```bash
# Basic scan — HTTPS only
./mcp-fuzz.sh -i live.txt

# Scan + JSON-RPC confirmation probe on all hits
./mcp-fuzz.sh -i live.txt -p

# Try both HTTP and HTTPS
./mcp-fuzz.sh -i live.txt -s https,http -p

# Increase throughput
./mcp-fuzz.sh -i live.txt -t 100 -r 300 -p
```

---

## Usage

```
./mcp-fuzz.sh [options]

  -i FILE       Subdomain input list       (default: live.txt)
  -w FILE       Wordlist path              (default: ./mcp-wordlist.txt)
  -o DIR        Output directory           (default: mcp-results)
  -t INT        ffuf threads per target    (default: 50)
  -r INT        Rate limit req/sec         (default: 100)
  -m CODES      Match HTTP status codes    (default: 200,201,301,302,307,401,403,405)
  -s SCHEMES    Schemes to probe           (default: https)
  -p            Run MCP JSON-RPC probe on all hits
  -x FLAGS      Extra flags passed to ffuf
  -v            Verbose — show ffuf output live
  -h            Help
```

### Input Format

`live.txt` accepts any of the following — normalisation is automatic:

```
example.com
https://api.example.com
http://staging.example.com/
sub.example.com
```

Blank lines and `#` comments are stripped. Duplicates are deduplicated.

---

## How It Works

**Stage 1 — Fuzzing**

For each host, ffuf iterates the wordlist against `{scheme}://{host}/FUZZ` with the `MCP-Protocol-Version: 2025-06-18` header set. Matching status codes are written to per-host JSON files under `mcp-results/raw/`.

**Stage 2 — JSON-RPC Probe** *(activated with `-p`)*

Every hit receives an actual MCP `initialize` request:

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": { "name": "mcp-probe", "version": "1.0" }
  },
  "id": 1
}
```

Confirmation triggers on any of:

| Signal | Indicator |
|:-------|:----------|
| JSON-RPC result body | `protocolVersion`, `serverInfo`, `capabilities` fields |
| SSE stream | `text/event-stream` + `data:` with JSON-RPC content |
| Version field | `mcp_version` or `mcp-version` in response |
| Capability lists | `tools`, `resources`, or `prompts` arrays |
| 405 on POST | Characteristic of SSE-only `/sse` endpoints |

Confirmed servers are written to `mcp-results/probes/mcp-confirmed.txt`.

---

## Output Structure

```
mcp-results/
├── raw/                        # Per-host ffuf JSON output
│   ├── api_example_com_https.json
│   └── ...
├── hits/                       # Parsed endpoint hits
│   ├── api_example_com_https.txt
│   ├── all-hits.txt            # Aggregated across all hosts
│   └── ...
└── probes/                     # JSON-RPC confirmation results
    ├── api_example_com_https.txt
    ├── mcp-confirmed.txt       # Final confirmed MCP servers
    └── ...
```

---

## Wordlist

`mcp-wordlist.txt` contains **176 entries** covering every known MCP endpoint pattern as of the 2025-06-18 spec and the 2026 roadmap proposals.

<details>
<summary>Categories</summary>

```
.well-known discovery          — /mcp, /mcp.json, /mcp-server, /mcp/server-card.json,
                                   /mcp-servers.json (SEP-1649, SEP-1960, IETF draft)

OAuth / auth metadata          — /oauth-authorization-server, /oauth-protected-resource,
                                   /openid-configuration (MCP auth spec §4)

Streamable HTTP transport      — /mcp, /mcp/, /api/mcp, /v1/mcp, /v2/mcp, /app/mcp

Legacy SSE transport           — /sse, /mcp/sse, /events, /mcp/messages, /messages

Framework defaults             — FastMCP (/mcp), Spring AI (/mcp/messages),
                                   Node SDK (/sse), FastAPI mounted paths

Capability endpoints           — /mcp/tools, /mcp/resources, /mcp/prompts,
                                   /mcp/capabilities, /mcp/sampling

Health / status                — /mcp/health, /mcp/ping, /mcp/status, /healthz

Server cards                   — /mcp/server-card.json (2026 roadmap)

LLM hint files                 — llms.txt, openapi.json, swagger.json

Commerce patterns              — /api/mcp, /storefront/mcp, /admin/mcp (Shopify et al.)

Gateway / proxy paths          — /mcp-gateway, /proxy/mcp, /agent/mcp, /tools/mcp
```

</details>

To extend the wordlist, append paths to `mcp-wordlist.txt`. Lines beginning with `#` are treated as comments and ignored by ffuf.

---

## Recommended Recon Pipeline

```bash
# 1. Enumerate subdomains
subfinder -d target.com -silent | httpx -silent -o live.txt

# 2. Discover MCP endpoints with confirmation
./mcp-fuzz.sh -i live.txt -p -s https,http

# 3. Review confirmed servers
cat mcp-results/probes/mcp-confirmed.txt

# 4. Deep-dive a specific confirmed server
curl -s -X POST https://api.target.com/mcp \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}' | jq .
```

---

## Background

The Model Context Protocol is an open standard for connecting LLM applications to external tools and services. Since its release in late 2024, adoption has grown rapidly — Shopify alone ships `/api/mcp` across millions of storefronts. However, standardised discovery mechanisms are still being formalised (SEP-1649, SEP-1960, IETF draft-serra-mcp-discovery-uri), meaning endpoint locations vary widely between implementations.

From a security perspective, MCP servers represent high-value targets:

- They expose tool execution surfaces that may reach internal systems
- OAuth flows introduce SSRF and redirect chains
- Many deployments rely on bearer tokens passed through AI clients
- The `tools/call` method can invoke arbitrary backend functionality
- Misconfigured CORS on SSE endpoints enables cross-origin reads

---

## Legal

This tool is intended for use against systems you own or have explicit written permission to test. Unauthorised scanning may violate computer fraud laws in your jurisdiction. The author assumes no liability for misuse.

---

<div align="center">

by **[0dayscyber](https://www.youtube.com/@0dayscyber)** · [HackerOne](https://hackerone.com) · [GitHub](https://github.com/theemperorspath)

</div>
