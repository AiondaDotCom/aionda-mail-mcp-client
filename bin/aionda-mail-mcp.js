#!/usr/bin/env node
/**
 * Aionda Mail MCP Proxy — CLI Entry Point
 *
 * Usage:
 *   AIONDA_API_KEY=tma_... AIONDA_VAULT_KEY=tmv_... npx @aiondadotcom/mail-mcp-client
 *
 * Or in Claude Code / OpenClaw MCP config:
 *   {
 *     "mcpServers": {
 *       "aionda-mail": {
 *         "command": "npx",
 *         "args": ["-y", "@aiondadotcom/mail-mcp-client"],
 *         "env": {
 *           "AIONDA_API_KEY": "tma_...",
 *           "AIONDA_VAULT_KEY": "tmv_...",
 *           "AIONDA_ENDPOINT": "https://mail.aionda.com"
 *         }
 *       }
 *     }
 *   }
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */
import('../dist/cli/aionda-mail-mcp.mjs').then(m => m.startStdioServer());
