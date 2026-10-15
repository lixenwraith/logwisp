import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";

// The drop-in directory make wasm writes over an earlier one's, served as a
// site serves it (?type= another content type) and loaded through lwconf.js;
// wasm_exec.js is imported first, as a page's script element runs it. make runs
// on its own, with make verify's toolchain: a GNU make's flags stop a BSD one.
const root = join(import.meta.dirname, "../..");
const tmp = mkdtempSync(join(tmpdir(), "lwconf-"));
const dir = join(tmp, "lwconf");
const go = process.env.GO ?? "go";
const env = { ...process.env, MAKEFLAGS: "", MFLAGS: "", MAKELEVEL: "" };
const wasm = (bin, ...vars) => execFileSync("make", ["-s", "wasm", `BIN_DIR=${bin}`, "VERSION=v0.0.0-node", `GO=${go}`, ...vars],
  { cwd: root, env, stdio: "ignore" });
mkdirSync(dir);
writeFileSync(join(dir, "stale.js"), "");
wasm(tmp);
const server = createServer((req, res) => {
  const { pathname, searchParams } = new URL(req.url, "http://localhost");
  const file = join(dir, basename(pathname));
  if (!existsSync(file)) return res.writeHead(404).end();
  res.setHeader("content-type", searchParams.get("type") ?? (file.endsWith(".wasm") ? "application/wasm" : "text/javascript"));
  res.end(readFileSync(file));
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
after(() => { server.close(); rmSync(tmp, { recursive: true, force: true }); });
const url = file => `http://127.0.0.1:${server.address().port}/${file}`;
const sri = file => "sha256-" + createHash("sha256").update(readFileSync(join(dir, file))).digest("base64");

const { load, fields, value, at, group } = await import(pathToFileURL(join(dir, "lwconf.js")));
await import(pathToFileURL(join(dir, "wasm_exec.js")));
const engine = await load({ wasmURL: url("lwconf.wasm"), wasmSRI: sri("lwconf.wasm") });
const schema = engine.schema().value;

test("make wasm writes one directory, which its manifest describes", () => {
  const manifest = JSON.parse(readFileSync(join(dir, "lwconf.json"), "utf8"));
  const files = readdirSync(dir).filter(f => f !== "lwconf.json").sort();
  assert.deepEqual(Object.keys(manifest.sha256).sort(), files);
  for (const file of files) {
    assert.equal(manifest.sha256[file], createHash("sha256").update(readFileSync(join(dir, file))).digest("hex"), file);
  }
  const version = execFileSync(go, ["env", "GOVERSION"], { cwd: root, encoding: "utf8" }).trim();
  assert.deepEqual([manifest.version, schema.version, manifest.go], ["v0.0.0-node", "v0.0.0-node", version]);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, "schema.json"), "utf8")), schema);
});

test("make wasm writes a commit's files the same at any time", () => {
  wasm(join(tmp, "again"), "BUILD_TIME=another");
  assert.equal(readFileSync(join(tmp, "again/lwconf/lwconf.json"), "utf8"), readFileSync(join(dir, "lwconf.json"), "utf8"));
});

test("load refuses an engine its integrity does not match, or a server does not have", async () => {
  await assert.rejects(load({ wasmURL: url("lwconf.wasm"), wasmSRI: sri("schema.json") }));
  await assert.rejects(load({ wasmURL: url("missing.wasm") }), { message: `${url("missing.wasm")}: 404` });
});

test("load takes an engine a server sends as plain bytes, counting them as they arrive", async () => {
  const api = globalThis.lwconf;
  delete globalThis.lwconf;
  try {
    const heard = [];
    const bytes = await load({ wasmURL: url("lwconf.wasm?type=application/octet-stream"), wasmSRI: sri("lwconf.wasm"), progress: n => heard.push(n) });
    assert.deepEqual(bytes.schema().value, schema);
    assert.ok(heard.every((n, i) => i === 0 || n > heard[i - 1]));
    assert.equal(heard.at(-1), readFileSync(join(dir, "lwconf.wasm")).length);
  } finally {
    globalThis.lwconf = api;
  }
});

// A path neither ending in '/' nor holding a glob is a question, in a preset
// or a pasted one, whose ask dirs answers
test("a preset path of unknown kind is asked, and dirs answers it", () => {
  const path = { path: "/var/log/app.log" }, dirs = { "/var/log/app.log": false };
  const asked = engine.preset("tail", path);
  assert.deepEqual([asked.path, asked.ask, asked.value], ["path", "/var/log/app.log", undefined]);
  assert.match(asked.error, /^path: "\/var\/log\/app\.log": a directory or a file\? end a directory with \//);
  const pasted = engine.parse("lw -p tail:path=/var/log/app.log", "command");
  assert.deepEqual([pasted.path, pasted.ask], ["path", "/var/log/app.log"]);
  const { value: pipelines } = engine.preset("tail", path, dirs);
  assert.deepEqual(value(pipelines, 0, { role: "source", id: "file" }), { directory: "/var/log", pattern: "app.log", from: "end" });
});

// The environment holds one pipeline, which a preset makes
test("a preset's pipeline, a single file answered by dirs, reads back from every form", () => {
  const path = { path: "/var/log/app.log" }, dirs = { "/var/log/app.log": false };
  const { value: pipelines } = engine.preset("serve", { ...path, allow: ["192.0.2.0/24", "198.51.100.7"] }, dirs);
  assert.deepEqual(value(pipelines, 0, { role: "source", id: "file" }), { directory: "/var/log", pattern: "app.log", from: "end" });
  assert.deepEqual(value(pipelines, 0, { role: "sink", id: "http" }, "acl.allow"), ["192.0.2.0/24", "198.51.100.7"]);
  assert.deepEqual(engine.parse("lw -p serve:path=/var/log/app.log,allow=192.0.2.0/24,allow=198.51.100.7", "command", dirs).value, pipelines);
  for (const { name } of schema.forms) {
    assert.deepEqual(engine.parse(engine.emit(pipelines, name).value, name).value, pipelines, name);
  }
  assert.deepEqual(engine.validate(pipelines).value, { pipelines, problems: [] });
});

// A value of the wrong kind is a problem as any other is, and the parts after
// it are still read
test("validate places every problem at its pipeline, node and key", () => {
  const { value: { problems } } = engine.validate([
    { name: "a", flow: { rate_limit: { policy: "bogus" }, filters: [{ patterns: ["("] }] }, plugin_sources: [{ type: "file" }],
      plugin_sinks: [{ id: "out", type: "tcp", config: { port: 9000, tls: { enabled: true } } }, { type: "http", config: { port: "x" } }] },
    { name: "a", plugin_sinks: [{ type: "tcp" }] },
  ]);
  const node = (role, id, index = 0) => ({ role, id, index });
  assert.deepEqual(problems.map(({ path, pipeline, node, key }) => ({ path, pipeline, node, key })), [
    { path: "pipelines[0].flow.rate_limit.policy", pipeline: 0, node: node("rate_limit", ""), key: "policy" },
    { path: "pipelines[0].flow.filters[0].patterns[0]", pipeline: 0, node: node("filters", "", 0), key: "patterns" },
    { path: "pipelines[0].plugin_sources[file].config.directory", pipeline: 0, node: node("source", "file"), key: "directory" },
    { path: "pipelines[0].plugin_sinks[out].config.tls", pipeline: 0, node: node("sink", "out"), key: "tls" },
    { path: "pipelines[0].plugin_sinks[http].config.port", pipeline: 0, node: node("sink", "http"), key: "port" },
    { path: "pipelines[1].name", pipeline: 1, node: undefined, key: "name" },
    { path: "pipelines[1].plugin_sources", pipeline: 1, node: undefined, key: "plugin_sources" },
    { path: "pipelines[1].plugin_sinks[tcp].config.port", pipeline: 1, node: node("sink", "tcp"), key: "port" },
  ]);
  assert.match(problems[3].text, /^listeners need cert_file/);
  assert.equal(problems[4].text, "not an integer");
  const placed = group(problems);
  assert.deepEqual(placed.get(at(0, { role: "sink", id: "out" })).get("tls"), [problems[3]]);
  assert.deepEqual(placed.get(at(0, { role: "rate_limit" })).get("policy"), [problems[0]]);
  assert.deepEqual([...placed.get(at(1)).keys()], ["name", "plugin_sources"]);
});

test("edits keep the engine's rules: free ids, retype's carry-over, a stage turned on", () => {
  let pipelines = [], node;
  const edit = op => {
    const r = engine.edit(pipelines, { pipeline: 0, ...op });
    assert.equal(r.error, undefined, JSON.stringify(op));
    ({ pipelines, node } = r.value);
    return node;
  };
  edit({ op: "add_pipeline", name: "p" });
  edit({ op: "add", role: "source", type: "null" });
  assert.deepEqual(edit({ op: "add", role: "source", type: "null" }), { role: "source", id: "null_2", index: 0 });
  const tcp = edit({ op: "add", role: "sink", type: "tcp" });
  edit({ op: "set", node: tcp, key: "port", values: ["9000"] });
  edit({ op: "set", node: tcp, key: "tls.enabled", values: ["true"] });
  assert.deepEqual(edit({ op: "retype", node: tcp, type: "http" }), { role: "sink", id: "http", index: 0 });
  assert.deepEqual(value(pipelines, 0, node), { port: 9000, tls: { enabled: true } });
  edit({ op: "unset", node, key: "tls.enabled" });
  edit({ op: "set", node: { role: "rate_limit" }, key: "entries_per_second", values: ["5"] });
  assert.deepEqual(value(pipelines, 0, { role: "rate_limit" }, "policy"), schema.flow[0].on.policy);
  edit({ op: "add", role: "filters", type: "exclude" });
  edit({ op: "add", role: "filters", type: "include" });
  assert.deepEqual(edit({ op: "move_filter", from: 1, to: 0 }), { role: "filters", id: "", index: 0 });
  assert.deepEqual([value(pipelines, 0, node, "type"), value(pipelines, 0, { role: "filters", index: 1 }, "type")], ["include", "exclude"]);
  edit({ op: "remove", node: { role: "source", id: "null" } });
  edit({ op: "rename_pipeline", name: "q" });
  assert.deepEqual([pipelines[0].name, pipelines[0].plugin_sources.map(s => s.id), value(pipelines, 0, { role: "sink", id: "http" })],
    ["q", ["null_2"], { port: 9000 }]);
  edit({ op: "remove_pipeline" });
  assert.deepEqual(pipelines, []);
});

test("fields are a node's keys, its tables' of the plugin's side as groups", () => {
  assert.deepEqual(schema.sources.find(p => p.type === "null").keys, []);
  const rows = fields(schema, "sink", "tcp_chain");
  const tls = rows.find(r => r.path === "tls");
  assert.ok(tls.rows.some(r => r.path === "tls.pin_sha256") && !tls.rows.some(r => r.path === "tls.self_signed"));
  assert.deepEqual(rows.find(r => r.path === "port").key.max, 65535);
  assert.equal(fields(schema, "rate_limit").find(r => r.path === "entries_per_second").placeholder, "(off)");
  assert.equal(fields(schema, "heartbeat").find(r => r.path === "interval_ms").placeholder, "1000");
  assert.equal(fields(schema, "sink", "file").find(r => r.path === "retention_hours").placeholder, "168");
});

test("a refused call answers why and where, and the engine keeps answering", () => {
  const refused = [
    [["parse", "lw --nope x", "command", "{}"], { error: /not a pipeline flag/ }],
    [["parse", "x=1", "environment", "{}"], { error: /^no LOGWISP_ pipeline variables$/ }],
    [["parse", "", "file", "{}"], { error: /no \[\[pipelines\]\]/ }],
    [["parse", "lw"], { error: /^usage: lwconf\.parse\(text, form, dirs\)/ }],
    [["parse", 5, "command", "{}"], { error: /^usage: / }],
    [["preset", "serve", JSON.stringify({ allow: 5 }), "{}"], { error: /^allow: takes a string/, path: "allow" }],
    [["edit", JSON.stringify([{ name: "p", plugin_sinks: [{ type: "tcp" }] }]),
      JSON.stringify({ op: "set", pipeline: 0, node: { role: "sink", id: "tcp" }, key: "port", values: ["x"] })],
      { error: /port: not an integer$/, path: "pipelines[0].plugin_sinks[tcp].config.port", pipeline: 0, key: "port" }],
    [["emit", JSON.stringify([{ name: "p" }]), "command"], { error: /plugin_sources: add a source; a pipeline needs at least one\n/, path: "pipelines[0].plugin_sources" }],
    [["emit", "[]", "yaml"], { error: /no form "yaml"/ }],
    [["edit", "[]", JSON.stringify({ op: "add_pipeline", nmae: "p" })], { error: /unknown field "nmae"/ }],
    [["edit", "[]", JSON.stringify({ op: "rename" })], { error: /^no op "rename" \(valid: add, add_pipeline/ }],
  ];
  for (const [args, want] of refused) {
    const got = JSON.parse(globalThis.lwconf[args[0]](...args.slice(1)));
    assert.equal(got.value, undefined, `${args}`);
    for (const [field, w] of Object.entries(want)) {
      if (w instanceof RegExp) assert.match(got[field], w, `${args}`);
      else assert.equal(got[field], w, `${args}`);
    }
  }
  assert.ok(engine.schema().value.sources.length > 0);
});
