# nvd-mcp

An MCP server that brings NIST National Vulnerability Database (NVD) intelligence
directly into Claude. Look up CVEs, search by product, and triage a list of
vulnerabilities into a prioritized risk report — all from a natural-language prompt.

Built with [FastMCP](https://github.com/jlowin/fastmcp) and the
[NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) (no API key required).

---

## Tools

| Tool | Description | Key inputs |
|------|-------------|------------|
| `lookup_cve` | Full details for a single CVE | `cve_id` — e.g. `"CVE-2021-44228"` |
| `search_cves` | CVEs by product or keyword, sorted by CVSS score | `keyword`, `max_results` (1–20, default 10) |
| `summarize_risk` | Severity breakdown + weighted risk score for a set of CVEs | `cve_ids` — list of 1–10 CVE IDs |

`summarize_risk` computes a composite risk score using the formula:

```
score = (CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1) / total_found
```

Score range: **0** (no risk) → **10** (all CRITICAL).

---

## Quickstart

### 1. Clone and install

```bash
git clone <repo-url> nvd-mcp
cd nvd-mcp
uv venv --python 3.13
uv pip install -e .
```

### 2. Verify the entry point

```bash
.venv/bin/nvd-mcp
```

You should see FastMCP start and wait on stdin — that confirms the server is working.
Press `Ctrl-C` to exit.

### 3. Connect to Claude Desktop

Open (or create) `~/Library/Application Support/Claude/claude_desktop_config.json`
and add the `nvd-mcp` entry:

```json
{
  "mcpServers": {
    "nvd-mcp": {
      "command": "/absolute/path/to/nvd-mcp/.venv/bin/nvd-mcp"
    }
  }
}
```

Replace `/absolute/path/to/nvd-mcp` with the actual path on your machine
(run `pwd` inside the project directory to get it).

Restart Claude Desktop. You should see `nvd-mcp` appear in the tools list.

---

## Example prompts

```
Look up CVE-2021-44228 and tell me how severe it is.
```

```
Find the 10 most critical CVEs affecting OpenSSL.
```

```
Summarize the risk for CVE-2021-44228, CVE-2022-22965, and CVE-2023-38545.
Give me a recommended remediation priority.
```

---

## Project layout

```
src/nvd_mcp/
├── server.py   # FastMCP app — tool definitions and entry point
├── client.py   # Async NVD API v2 HTTP client with retry/backoff
└── models.py   # Pydantic v2 models: NVD response parsing + tool output types
```

## Rate limiting

The NVD public API allows **5 requests per 30 seconds** without an API key.
`summarize_risk` staggers its requests automatically. If you need higher throughput,
register for a free NVD API key and set the `NVD_API_KEY` environment variable
(the server will pick it up via the `Authorization` header — see `client.py`).

> **Note:** `NVD_API_KEY` support is a one-line addition to the `NvdClient`
> headers dict; it is not wired up in this demo to keep the setup keyless.

---

## Development

```bash
# Type check
PYTHONPATH=src .venv/bin/pyright

# Run tests
PYTHONPATH=src .venv/bin/pytest
```
