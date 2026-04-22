# Modei

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

The trust layer for AI agents. Gates protect your tools. Passports authorize your agents. Everything verified locally.

This repo contains three packages:

| Package | Directory | Published as | Description |
|---------|-----------|--------------|-------------|
| **MCP Server** | [`mcp/`](mcp/) | [`modei-mcp`](https://www.npmjs.com/package/modei-mcp) on npm | MCP server for managing Modei infrastructure from Claude, Cursor, or any MCP client |
| **Python SDK** | [`python/`](python/) | [`modei-python`](https://pypi.org/project/modei-python/) on PyPI | Python SDK for REST API and self-issued passport workflows |
| **TypeScript SDK** | [`typescript/`](typescript/) | `modei-typescript` on npm | TypeScript SDK for REST API and self-issued passport workflows *(coming soon)* |

---

## MCP Server

[![npm version](https://img.shields.io/npm/v/modei-mcp)](https://www.npmjs.com/package/modei-mcp)

```bash
npx modei-mcp
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "modei": {
      "command": "npx",
      "args": ["modei-mcp"],
      "env": {
        "MODEI_API_KEY": "mod_live_xxxxxxxx"
      }
    }
  }
}
```

See [`mcp/README.md`](mcp/README.md) for full documentation.

---

## Python SDK

[![PyPI version](https://img.shields.io/pypi/v/modei-python)](https://pypi.org/project/modei-python/)

```bash
pip install modei-python
```

```python
from modei import ModeiClient

client = ModeiClient(api_key="mod_live_xxxxxxxx")
gates = client.list_gates()
```

See [`python/README.md`](python/README.md) for full documentation.

---

## TypeScript SDK

*Coming soon.*

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
