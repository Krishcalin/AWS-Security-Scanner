# OverWatch MCP server

A local, read-only MCP server over a **finished** OverWatch scan report. It lets an
analyst ask questions in natural language — *"what should I fix first?"*, *"is this
account ready for a SOC 2 walkthrough?"* — instead of reading a JSON report.

It cannot scan, cannot change anything, and never talks to AWS.

---

## Read this before you enable it

**The server is inside the OverWatch boundary. Your MCP client is not.**

OverWatch is sold on a zero-telemetry guarantee, enforced in CI by
`tests/test_zero_telemetry.py`: every network egress in the product is either an AWS API
call or a seam you explicitly configured. That guarantee is about **our** code, and it
remains true with this server running — the server itself opens no sockets and imports no
network primitive.

It does not, and cannot, cover what happens next. Your MCP client — Claude Code, Cursor,
Claude Desktop, or anything else — takes what this server returns and sends it to whatever
model it is configured with. If that model is hosted, your findings leave your
environment. We cannot see that hop, cannot log it, and cannot prevent it.

So the boundary is enforced here rather than described:

| | |
|---|---|
| **The server refuses to start** without `OVERWATCH_MCP_ACK_CLIENT_EGRESS=1` | the egress becomes a decision somebody made, not a default nobody noticed |
| **Identifiers are redacted by default** | the analysis travels; the ARNs stay home |
| **Every tool call is written to an audit log** | we can't audit what your client did, but we can tell you exactly what left the server |

### What this actually changes

Being straight about the size of it: this is **not a new capability**. A scan already
writes a complete JSON report to disk — every finding, ARN, account ID and attack path —
and you could point any tool at that file today. What an MCP server adds is convenience,
and OverWatch's name on the path.

That is a smaller delta than it first looks. It is also not nothing, because defaults
drive behaviour: one line in a config file is a different act from deliberately pasting a
security report into a chat window. The gate exists to keep it an act.

---

## Running it

```bash
# 1. Produce a report
python -m engine.aws_live_scanner --json reports/scan.json

# 2. Acknowledge the client boundary, then run the server
export OVERWATCH_MCP_ACK_CLIENT_EGRESS=1
python -m hub.cnapp_mcp --report reports/scan.json
```

Without the acknowledgement the server prints its reasoning to stderr and exits `2`.

### Client configuration

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "python",
      "args": ["/path/to/cnapp_mcp.py", "--report", "/path/to/reports/scan.json"],
      "env": { "OVERWATCH_MCP_ACK_CLIENT_EGRESS": "1" }
    }
  }
}
```

### Options

| Variable | Default | Meaning |
|---|---|---|
| `OVERWATCH_MCP_ACK_CLIENT_EGRESS` | *(unset)* | `1` to start at all. |
| `OVERWATCH_MCP_SERVE_IDENTIFIERS` | *(unset)* | `1` to serve real ARNs, account IDs and IPs. |
| `OVERWATCH_MCP_REPORT` | *(unset)* | Report path, if you'd rather not pass `--report`. |
| `OVERWATCH_MCP_AUDIT` | `evidence/mcp_audit.jsonl` | Where the per-call audit log goes. |

---

## Redaction

By default, ARNs, 12-digit account IDs and IPv4 addresses are replaced with stable
pseudonyms:

```
Bucket arn:aws:s3:::prod-customer-pii in account 123456789012 is public (203.0.113.7)
                              ↓
Bucket arn:aws:s3:::s3-7f3a2b in account acct-4e91c0 is public (ip-8b21df)
```

The finding survives; the identity does not. Pseudonyms are **stable within one server
process**, so you can say "that same bucket again" across several answers, and
**different across processes**, so two transcripts can't be joined on them — which
matters precisely because those transcripts end up somewhere we don't control.

To map a pseudonym back to a real resource, read your own report. That lookup happens on
your machine, in your terminal, and nowhere else.

`overwatch_check_reference` is never redacted: it returns OverWatch's own risk and
remediation text, which contains no customer data and whose example ARNs would be
mangled by redaction.

---

## Running against a local model

**This is the only configuration where the server's output stays inside your boundary**,
and it is the one to use on sovereign, air-gapped or regulated estates.

Point an MCP-capable client at a locally-hosted model — Ollama, llama.cpp, LM Studio, or
any OpenAI-compatible endpoint on `localhost` — and configure the OverWatch server as
above. Nothing leaves the host.

Two things to confirm before treating it as air-gapped, because both have caught people:

1. **The client is the thing that matters, not the model.** A client pointed at a local
   model may still send telemetry, crash reports or completion logs elsewhere. Check its
   settings, not just its model configuration.
2. **Verify rather than assume.** Watch the host's egress while you run a few queries. If
   you can't observe it, don't claim it.

With a local model you can reasonably set `OVERWATCH_MCP_SERVE_IDENTIFIERS=1` — the
identifiers aren't going anywhere. That is the trade the flag exists for.

---

## Tools

| Tool | Returns |
|---|---|
| `overwatch_scan_summary` | Posture score and grade, counts by severity, scan time. |
| `overwatch_coverage` | **What the scan could not see** — refused checks and the exact IAM action missing for each. |
| `overwatch_findings` | Findings, filterable by severity, status, section or check ID. |
| `overwatch_attack_paths` | Correlated attack paths and choke points. |
| `overwatch_check_reference` | Risk, impact and remediation for one check ID. No customer data. |

`overwatch_coverage` is deliberately prominent. The server's `initialize` instructions
tell the model to call it before describing anything as clean, because **an unevaluated
control is not a passing control** — and a language model asked "am I secure?" over a
partial scan will otherwise answer from what it was given.

### Prompts

`triage_worst_first`, `explain_a_check`, `audit_readiness` — each written to consult
coverage before drawing a conclusion.

---

## What is and isn't guaranteed

**Tested** (`tests/test_mcp.py`, and Section G of `tests/test_zero_telemetry.py`):

- the server cannot start without the acknowledgement
- it imports no network primitive, and never imports the scanner or boto3
- redaction is the default construction, and covers dict keys as well as values
- nothing but MCP messages reaches stdout
- every tool call is audited, and the audit stores a digest rather than a second copy of
  your findings

**Not guaranteed, and not testable by us:** that your client kept the data inside your
boundary. That is the hop the gate makes you acknowledge, and the reason the local-model
path is documented above.
