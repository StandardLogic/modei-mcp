# modus-mcp

[![PyPI version](https://img.shields.io/pypi/v/modus-mcp)](https://pypi.org/project/modus-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**The trust layer for AI agents.** Gates protect your tools. Passports authorize your agents. Everything verified locally.

Python client for the [Modus](https://modusoperator.com) REST API. Manage gates, passports, attestations, constraints, catalogs, enforcement, commerce, and billing programmatically.

---

## What is Modus?

[Modus](https://modusoperator.com) is an open protocol that adds a lightweight trust layer for the agentic web. It has two sides:

**Gates** protect your tools, APIs, and MCP servers. A Gate is a verification checkpoint — you define a permission catalog of what's allowed, and incoming agent requests are checked against it locally, with no network round-trip. Every decision produces a signed attestation for a tamper-evident audit trail.

**Passports** are signed credentials that agents carry. Each passport specifies who issued it, what the agent is allowed to do, and under what constraints — scoped to specific actions, resources, and time windows.

This SDK lets you manage both sides — gates, passports, attestations, constraints, enforcement, and commerce — from your own Python applications, scripts, and agent frameworks.

---

## Prerequisites

- A **Modus account** — sign up at the [Modus Dashboard](https://modusoperator.com)
- An **API key** — generate one from the dashboard
- **Python 3.9+**

---

## Installation

```bash
pip install modus-mcp
```

---

## Quick Start

```python
from modus import ModusClient

client = ModusClient(api_key="uni_live_xxxxxxxx")

# Create a gate
gate = client.create_gate(name="My Service", gate_id="gate_my-service")

# Issue a passport
passport = client.issue_passport(
    "gate_my-service",
    agent_id="agent-001",
    agent_name="My Agent",
    permissions=["read", "write"],
    expires_in="7d",
)

# Check authorization
result = client.check_gate(
    "gate_my-service",
    action="read",
    passport_id=passport["passport_id"],
)
print(result["allowed"])  # True

# Enforce with constraints
enforcement = client.enforce_action(
    passport_id=passport["passport_id"],
    action="write",
    cost_cents=500,
)
print(enforcement["decision"])  # "PERMIT"

client.close()
```

### Async

```python
import asyncio
from modus import AsyncModusClient

async def main():
    async with AsyncModusClient(api_key="uni_live_xxxxxxxx") as client:
        gates = await client.list_gates()
        print(f"Found {len(gates)} gates")

        for gate in gates:
            passports = await client.list_passports(gate["gate_id"])
            print(f"  {gate['name']}: {len(passports)} passports")

asyncio.run(main())
```

### Context Manager

Both clients support context managers for automatic cleanup:

```python
with ModusClient(api_key="uni_live_xxxxxxxx") as client:
    gates = client.list_gates()
```

---

## API Coverage

### Gates

```python
client.list_gates()
client.get_gate("gate_my-service")
client.create_gate(name="My Service", gate_id="gate_my-service")
client.update_gate("gate_my-service", name="Updated Name")
client.delete_gate("gate_my-service")
```

### Gate Check

```python
client.check_gate("gate_my-service", action="read", passport_id="pp_xxx")
client.authorize_dry_run(gate_id="gate_my-service", passport_id="pp_xxx", action="read")
```

### Passports

```python
client.list_passports("gate_my-service")
client.get_passport("gate_my-service", "pp_xxx")
client.issue_passport("gate_my-service", agent_id="agent-001", permissions=["read"])
client.revoke_passport("gate_my-service", "pp_xxx")
client.reissue_passport("pp_xxx", accept_catalog_version=2)
```

### Attestations

```python
client.list_attestations("gate_my-service", limit=50)
client.record_attestation("gate_my-service", passport_id="pp_xxx", permission="read", tool_name="search", result="allowed")
```

### Permission Catalog

```python
client.get_catalog("gate_my-service")
client.create_catalog("gate_my-service", permissions=[...])
client.publish_catalog("gate_my-service", change_summary="Added search permission")
client.list_catalog_versions("gate_my-service")
client.get_catalog_version("gate_my-service", version=1)
client.get_catalog_impact("gate_my-service")
```

### Constraints

```python
client.get_constraints("pp_xxx")
client.set_constraints("pp_xxx", {"read": {"core:rate:max_per_minute": 100}})
client.list_constraint_types(category="cost")
client.list_constraint_templates(category="security")
client.apply_constraint_template("pp_xxx", "conservative-agent")
client.create_constraint_template(slug="my-template", name="My Template", constraints={...})
```

### Enforcement (CEL)

```python
client.enforce_action(passport_id="pp_xxx", action="write", cost_cents=500)
client.list_enforcement_attestations("pp_xxx", decision="BLOCK")
client.get_enforcement_attestation("enf_xxx")
client.verify_enforcement_attestation("enf_xxx")
```

### Anonymous Access

```python
client.get_anonymous_policy("gate_my-service")
client.set_anonymous_policy("gate_my-service", enabled=True, allowed_actions=["read"])
client.get_anonymous_log("gate_my-service")
```

### Commerce

```python
# Service discovery
results = client.discover_services("flights:search", max_price_cents=100, sort="price_asc")

# Consumption metering
attestation = client.issue_consumption_attestation(
    passport_id="pp_xxx",
    gate_id="gate_my-service",
    action="flights:search",
    outcome="success",
)

# Billing & settlement
client.generate_settlement(gate_id="gate_my-service", period_type="monthly", period_start="2025-01-01", period_end="2025-01-31")
client.list_settlements(gate_id="gate_my-service", status="pending")
client.get_settlement("stl_xxx")
client.update_settlement_status("stl_xxx", "invoiced")

# SLA compliance
sla = client.get_sla_compliance("gate_my-service", period_start="2025-01-01", period_end="2025-01-31")
```

### Cumulative State

```python
client.get_cumulative_state("pp_xxx")
client.reset_cumulative_state("pp_xxx", window_type="daily")
```

### API Keys

```python
client.list_api_keys()
client.create_api_key(name="My Key", scopes=["gates:read", "passports:write"])
client.revoke_api_key("key_xxx")
```

---

## Cryptographic Verification

The SDK includes local verification utilities for Ed25519 signatures and RFC 8785 content hashing:

```python
from modus import verify_attestation_signature, verify_content_hash, compute_content_hash

# Verify an attestation signature locally
valid = verify_attestation_signature(
    attestation_json='{"gate_id":"gate_my-service",...}',
    signature_b64="base64-sig...",
    public_key_b64="base64-key...",
)

# Verify a catalog content hash
matches = verify_content_hash(catalog_snapshot, expected_hash)

# Compute a content hash (RFC 8785 canonical JSON + SHA-256)
hash_hex = compute_content_hash({"key": "value"})
```

---

## Error Handling

All API errors are raised as typed exceptions:

```python
from modus import (
    ModusError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    ConflictError,
)

try:
    client.get_gate("gate_nonexistent")
except NotFoundError as e:
    print(f"Not found: {e}")
    print(f"Status: {e.status_code}")  # 404
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.retry_after}s")
except ModusError as e:
    print(f"API error: {e} (HTTP {e.status_code})")
```

| Exception | HTTP Status |
|-----------|-------------|
| `AuthenticationError` | 401 |
| `AuthorizationError` | 403 |
| `NotFoundError` | 404 |
| `ConflictError` | 409 |
| `ValidationError` | 400, 422 |
| `RateLimitError` | 429 |
| `ModusError` | All other errors |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MODUS_API_KEY` | Yes | — | Your Modus API key (`uni_live_*` or `uni_test_*`) |
| `MODUS_API_URL` | No | `https://modusoperator.com` | API base URL (override for local dev) |

You can also pass these directly to the client:

```python
client = ModusClient(api_key="uni_live_xxx", base_url="http://localhost:3000")
```

---

## Local Development

To test against a local development dashboard:

```python
client = ModusClient(
    api_key="uni_test_xxxxxxxx",
    base_url="http://localhost:3000",
)
```

To install the SDK in editable mode from source:

```bash
git clone https://github.com/StandardLogic/modus-mcp.git
cd modus-mcp/python
pip install -e ".[dev]"
```

---

## Learn More

- [Modus Dashboard](https://modusoperator.com) — Create your account and manage gates, passports, and API keys
- [Documentation & Guides](https://modusoperator.com)
- [Protocol Specification](https://github.com/uniplexprotocol/uniplex)
- [MCP SDK (TypeScript)](https://www.npmjs.com/package/modus-mcp-sdk) · [MCP SDK (Python)](https://pypi.org/project/modus-mcp-sdk/)
- [Management MCP Server (TypeScript)](https://www.npmjs.com/package/modus-mcp)
- [Discussions](https://github.com/StandardLogic/modus-mcp/discussions) — Questions and ideas

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)

Building the trust infrastructure for AI agents.
