# Modus

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

The trust layer for AI agents. Gates protect your tools. Passports authorize your agents. Everything verified locally.

This repo contains two packages:

| Package | Directory | Published as | Description |
|---------|-----------|-------------|-------------|
| **MCP Server** | [`typescript/`](typescript/) | [`modus-mcp`](https://www.npmjs.com/package/modus-mcp) on npm | MCP server for managing Modus infrastructure from Claude, Cursor, or any MCP client |
| **Python SDK** | [`python/`](python/) | [`modus-sdk`](https://pypi.org/project/modus-sdk/) on PyPI | Python REST API client for managing gates, passports, and enforcement policies |

---

## MCP Server (TypeScript)

[![npm version](https://img.shields.io/npm/v/modus-mcp)](https://www.npmjs.com/package/modus-mcp)

```bash
npx modus-mcp
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "modus": {
      "command": "npx",
      "args": ["modus-mcp"],
      "env": {
        "MODUS_API_KEY": "mod_live_xxxxxxxx"
      }
    }
  }
}
```

See [`typescript/README.md`](typescript/README.md) for full documentation.

---

## Python SDK

[![PyPI version](https://img.shields.io/pypi/v/modus-sdk)](https://pypi.org/project/modus-sdk/)

```bash
pip install modus-sdk
```

```python
from modus import ModusClient

client = ModusClient(api_key="mod_live_xxxxxxxx")
gates = client.list_gates()
```

See [`python/README.md`](python/README.md) for full documentation.

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
