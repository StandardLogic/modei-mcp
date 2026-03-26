# Modus MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

MCP server for managing [Modus](https://modusoperator.com) gates, catalogs, and passports via Claude Desktop, claude.ai, or any MCP client.

---

## TypeScript

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
        "MODUS_API_KEY": "uni_live_xxxxxxxx"
      }
    }
  }
}
```

See [`typescript/README.md`](typescript/README.md) for full documentation.

---

## Python

[![PyPI version](https://img.shields.io/pypi/v/modus-mcp)](https://pypi.org/project/modus-mcp/)

```bash
pip install modus-mcp
```

```python
from modus import ModusClient

client = ModusClient(api_key="uni_live_xxxxxxxx")
gates = client.list_gates()
```

See [`python/README.md`](python/README.md) for full documentation.

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
