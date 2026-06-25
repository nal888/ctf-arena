#!/usr/bin/env bash
# Sets up the bundled (ours) CTF MCP servers: installs the `mcp` dep and prints the
# ready-to-paste ~/.claude.json entries with correct absolute paths. Downloaded servers: see README.md.
set -euo pipefail
ARENA="$(cd "$(dirname "$0")/.." && pwd)"

echo "Installing the 'mcp' Python package (needed by magic + netsession)..."
python3 -m pip install -q --user mcp 2>/dev/null || pip install -q mcp || echo "  (install 'mcp' manually: pip install mcp)"

echo
echo "Add these to ~/.claude.json under \"mcpServers\", then restart Claude Code:"
echo "-----------------------------------------------------------------------"
cat <<JSON
    "magic": {
      "command": "python3",
      "args": ["$ARENA/mcp/ours/magic-mcp/server.py"]
    },
    "netsession": {
      "command": "python3",
      "args": ["$ARENA/mcp/ours/netsession/server.py"]
    }
JSON
echo "-----------------------------------------------------------------------"
echo "Downloaded servers (kali_mcp, radare2, ghidra, burp, …): see mcp/README.md"
