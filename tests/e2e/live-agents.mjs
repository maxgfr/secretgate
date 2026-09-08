#!/usr/bin/env node
// Real CLI processes against a loopback model endpoint. No account or paid model
// needed. Assert on the requests the agent sends, not on its final prose.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const bundle = join(root, "scripts/secretgate.mjs");
const mcp = join(root, "tests/e2e/mcp-fixture.mjs");
const fake = "ghp_" + ["aB3dE6", "gH9jK2", "mN5pQ8", "sT1vW4", "yZ7bC0", "dF6hJ9"].join("");
const agents = process.argv.slice(2).length ? process.argv.slice(2) : ["claude-code", "codex", "opencode"];
const requested = new Set(["claude-code", "codex", "opencode"]);
for (const agent of agents) assert(requested.has(agent), `Unknown agent: ${agent}`);

function run(command, args, options) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (x) => {
      stdout += x;
    });
    child.stderr.on("data", (x) => {
      stderr += x;
    });
    const timer = setTimeout(() => child.kill("SIGTERM"), 60000);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolveRun({ code, signal, stdout, stderr });
    });
  });
}

function anthropic(res, model, tool) {
  const content = tool ? [{ type: "tool_use", id: `tool_${Date.now()}`, name: tool.name, input: tool.args }] : [{ type: "text", text: "Audit complete." }];
  const message = {
    id: `msg_${Date.now()}`,
    type: "message",
    role: "assistant",
    model,
    content: [],
    stop_reason: null,
    stop_sequence: null,
    usage: { input_tokens: 10, output_tokens: 1 },
  };
  res.writeHead(200, { "content-type": "text/event-stream" });
  const emit = (type, payload) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`);
  emit("message_start", { message });
  for (const [index, block] of content.entries()) {
    emit("content_block_start", { index, content_block: block.type === "tool_use" ? { ...block, input: {} } : { type: "text", text: "" } });
    emit("content_block_delta", {
      index,
      delta: block.type === "tool_use" ? { type: "input_json_delta", partial_json: JSON.stringify(block.input) } : { type: "text_delta", text: block.text },
    });
    emit("content_block_stop", { index });
  }
  emit("message_delta", { delta: { stop_reason: tool ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 10 } });
  emit("message_stop", {});
  res.end();
}

function responses(res, model, tool) {
  const id = `resp_${Date.now()}`;
  const output = tool
    ? [
        {
          type: tool.custom ? "custom_tool_call" : "function_call",
          id: "fc_" + id,
          call_id: "call_" + id,
          name: tool.name,
          ...(tool.custom ? { input: tool.args } : { arguments: JSON.stringify(tool.args) }),
          ...(tool.namespace ? { namespace: tool.namespace } : {}),
          status: "completed",
        },
      ]
    : [
        {
          type: "message",
          id: "msg_" + id,
          role: "assistant",
          content: [{ type: "output_text", text: "Audit complete.", annotations: [] }],
          status: "completed",
        },
      ];
  const response = {
    id,
    object: "response",
    created_at: Math.floor(Date.now() / 1000),
    model,
    status: "completed",
    output,
    usage: { input_tokens: 10, output_tokens: 10, total_tokens: 20 },
  };
  res.writeHead(200, { "content-type": "text/event-stream" });
  let sequence_number = 0;
  const emit = (type, payload) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: sequence_number++, ...payload })}\n\n`);
  emit("response.created", { response: { ...response, status: "in_progress", output: [] } });
  for (const [output_index, item] of output.entries()) {
    emit("response.output_item.added", { output_index, item });
    emit("response.output_item.done", { output_index, item });
  }
  emit("response.completed", { response });
  res.end();
}

for (const agent of agents) {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "secretgate-live-")));
  const project = join(scratch, "project");
  mkdirSync(project);
  const state = join(scratch, "vault");
  const env = {
    ...process.env,
    SECRETGATE_HOME: state,
    SECRETGATE_DISABLE: "0",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    XDG_CONFIG_HOME: join(scratch, "config"),
    XDG_DATA_HOME: join(scratch, "data"),
    XDG_CACHE_HOME: join(scratch, "cache"),
    XDG_STATE_HOME: join(scratch, "state"),
  };
  for (const key of ["ANTHROPIC_AUTH_TOKEN", "OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR"]) delete env[key];
  let phase = "prompt",
    turn = 0;
  const requests = [];
  let failure;
  const server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    if (!req.url.includes("messages") && !req.url.includes("responses")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
      return;
    }
    if (req.url.includes("count_tokens")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"input_tokens":10}');
      return;
    }
    try {
      const body = JSON.parse(raw);
      requests.push({ phase, body });
      assert(!raw.includes(fake), `${agent}: RAW SYNTHETIC SECRET REACHED MODEL REQUEST (${phase})`);
      if (phase === "prompt") {
        anthropic(res, body.model, undefined);
        return;
      }
      const tools = (
        body.tools ??
        (agent === "codex"
          ? [
              { name: "exec_command", namespace: "functions" },
              { name: "apply_patch", type: "custom", namespace: "functions" },
              { name: "emit", namespace: "mcp__audit" },
            ]
          : [])
      ).flatMap((t) => (t.type === "namespace" ? t.tools.map((x) => ({ ...x, namespace: t.name })) : [t]));
      const names = tools.map((t) => t.name);
      let tool;
      if (!tools.length) {
        if (agent === "codex") responses(res, body.model);
        else anthropic(res, body.model);
        return;
      }
      if (turn++ === 0) {
        const name =
          phase === "mcp"
            ? (names.find((n) => n.endsWith("_emit") || n === "emit") ?? "mcp__audit__emit")
            : agent === "claude-code"
              ? "Read"
              : agent === "opencode"
                ? "read"
                : names.find((n) => n === "exec_command" || n === "shell");
        assert(name, `Missing read/shell tool: ${names.join(",")}`);
        tool = {
          name,
          args:
            phase === "mcp"
              ? {}
              : agent === "claude-code"
                ? { file_path: join(project, "ci-values.txt") }
                : agent === "opencode"
                  ? { filePath: join(project, "ci-values.txt") }
                  : name === "exec_command"
                    ? { cmd: "cat ci-values.txt" }
                    : { command: ["cat", "ci-values.txt"] },
          namespace: tools.find((t) => t.name === name)?.namespace,
        };
      } else if (turn === 2) {
        const placeholder = raw.match(/SECRETGATE_[a-f0-9]{12,16}/)?.[0];
        assert(placeholder, `${agent}: no redacted tool result in the next request`);
        if (agent === "codex") {
          const spec = tools.find((t) => t.name === "apply_patch");
          assert(spec, "Missing apply_patch tool");
          const patch = `*** Begin Patch\n*** Add File: copy.txt\n+CI_TOKEN=${placeholder}\n*** End Patch`;
          tool = { name: "apply_patch", custom: spec.type === "custom", args: spec.type === "custom" ? patch : { patch }, namespace: spec.namespace };
        } else
          tool = {
            name: agent === "claude-code" ? "Write" : "write",
            args:
              agent === "claude-code"
                ? { file_path: join(project, "copy.txt"), content: `CI_TOKEN=${placeholder}\n` }
                : { filePath: join(project, "copy.txt"), content: `CI_TOKEN=${placeholder}\n` },
          };
      }
      if (agent === "codex") responses(res, body.model, tool);
      else anthropic(res, body.model, tool);
    } catch (error) {
      failure = error;
      res.writeHead(500);
      res.end("audit assertion failed");
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    let command, args;
    if (agent === "claude-code") {
      env.ANTHROPIC_BASE_URL = url;
      env.ANTHROPIC_API_KEY = "test";
      execFileSync("node", [bundle, "install", "--claude-code", "--project"], { cwd: project, env, stdio: "pipe" });
      command = "claude";
      args = [
        "-p",
        "--model",
        "claude-fable-5-1",
        "--setting-sources",
        "project",
        "--strict-mcp-config",
        "--mcp-config",
        JSON.stringify({ mcpServers: { audit: { command: "node", args: [mcp] } } }),
        "--permission-mode",
        "acceptEdits",
        "--tools",
        "Read,Write,Bash,mcp__audit__emit",
        "--allowedTools",
        "mcp__audit__emit",
        "--output-format",
        "json",
        "--no-session-persistence",
      ];
    } else if (agent === "codex") {
      const config = join(scratch, "codex-real");
      mkdirSync(config);
      const alias = join(scratch, "codex-alias");
      symlinkSync(config, alias, "junction");
      env.CODEX_HOME = alias;
      writeFileSync(
        join(config, "config.toml"),
        `model = "gpt-5.6-sol"\nmodel_provider = "audit"\n[model_providers.audit]\nname = "Local audit"\nbase_url = "${url}/v1"\nwire_api = "responses"\n[mcp_servers.audit]\ndefault_tools_approval_mode = "approve"\ncommand = "node"\nargs = [${JSON.stringify(mcp)}]\n`,
      );
      execFileSync("node", [bundle, "install", "--codex"], { cwd: project, env, stdio: "pipe" });
      command = "codex";
      args = ["exec", "--skip-git-repo-check", "--json", "--ephemeral", "--sandbox", "workspace-write"];
    } else {
      execFileSync("node", [bundle, "install", "--opencode"], { cwd: project, env, stdio: "pipe" });
      writeFileSync(
        join(env.XDG_CONFIG_HOME, "opencode", "opencode.json"),
        JSON.stringify({
          model: "anthropic/claude-fable-5-1",
          provider: { anthropic: { options: { baseURL: url + "/v1", apiKey: "test" } } },
          permission: "allow",
          mcp: { audit: { type: "local", command: ["node", mcp], enabled: true } },
        }),
      );
      command = "opencode";
      args = ["run", "--format", "json"];
    }
    const version = execFileSync(command, ["--version"], { encoding: "utf8" }).trim();
    const pasted = await run(command, [...args, "Token " + fake], { cwd: project, env });
    if (failure) throw failure;
    assert(pasted.code === 0 || (agent === "claude-code" && pasted.stdout.includes("blocked")), `Prompt process failed: ${pasted.stderr.slice(-700)}`);
    if (agent !== "opencode") assert.equal(requests.length, 0, `${agent}: blocked prompt still sent a request`);
    else assert(requests.length > 0, "OpenCode prompt did not reach loopback model");
    console.log(`PASS ${agent} ${version}: real prompt interception`);
    for (const scenario of ["roundtrip", "mcp"]) {
      phase = scenario;
      turn = 0;
      rmSync(join(project, "copy.txt"), { force: true });
      writeFileSync(join(project, "ci-values.txt"), "CI_TOKEN=" + fake + "\n");
      const result = await run(
        command,
        [
          ...args,
          phase === "mcp"
            ? "Call the audit MCP emit tool, then write its CI_TOKEN value into copy.txt."
            : "Read ci-values.txt, then copy its CI_TOKEN line into copy.txt using the file writing tool.",
        ],
        { cwd: project, env },
      );
      if (failure) {
        console.error((result.stderr + result.stdout).replaceAll(fake, "[FAKE]").slice(-5000));
        throw failure;
      }
      assert.equal(result.code, 0, `Roundtrip process failed: ${result.stderr.slice(-700)}`);
      assert(turn >= 3, `${agent}: incomplete tool loop (${turn}); ${result.stdout.slice(-900)}`);
      assert(readFileSync(join(project, "copy.txt"), "utf8").includes(fake), "Real secret was not restored on disk");
      console.log(
        `PASS ${agent} ${phase}: result redacted before model request, restore on disk, ${requests.filter((r) => r.phase === phase).length} requests inspected`,
      );
    }
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    rmSync(scratch, { recursive: true, force: true });
  }
}
