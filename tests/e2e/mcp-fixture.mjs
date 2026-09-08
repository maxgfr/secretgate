#!/usr/bin/env node
// A local MCP fixture. All credentials are deliberately synthetic.
import { createInterface } from "node:readline";
const fake = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.id === undefined) continue;
  let result;
  if (request.method === "initialize")
    result = { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "secretgate-audit", version: "1.0.0" } };
  else if (request.method === "tools/list")
    result = {
      tools: [
        { name: "emit", description: "Return a synthetic audit credential.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
      ],
    };
  else if (request.method === "tools/call")
    result = { content: [{ type: "text", text: "CI_TOKEN=" + fake }], structuredContent: { token: fake }, isError: false };
  else result = {};
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) + "\n");
}
