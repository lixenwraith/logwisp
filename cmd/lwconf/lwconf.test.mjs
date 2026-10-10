import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Built by make wasm and started as the page starts it: the toolchain's loader
// beside the module, main running until the page closes. The make run is its
// own: a parent GNU make's flags would stop a BSD one.
const dir = mkdtempSync(join(tmpdir(), "lwconf-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const made = execFileSync("make", ["-s", "wasm", `BIN_DIR=${dir}`, "VERSION=v0.0.0-node"], {
  cwd: join(import.meta.dirname, "../.."), encoding: "utf8",
  env: { ...process.env, MAKEFLAGS: "", MFLAGS: "", MAKELEVEL: "" },
});
await import(pathToFileURL(join(dir, "wasm_exec.js")));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(join(dir, "lwconf.wasm")), go.importObject);
go.run(instance);
const call = (name, ...args) => JSON.parse(globalThis.lwconf[name](...args));

test("make wasm stamps the version and prints both checksums", () => {
  for (const file of ["lwconf.wasm", "wasm_exec.js"]) {
    const sum = createHash("sha256").update(readFileSync(join(dir, file))).digest("hex");
    assert.match(made, new RegExp(`^${sum} +${file.replace(".", "\\.")}$`, "m"));
  }
  assert.equal(call("schema").value.version, "v0.0.0-node");
});

// Off the host a directory path ends in '/'
test("a preset's pipelines, written as a command line, parse and validate back to themselves", () => {
  const { value: pipelines } = call("preset", "tail", JSON.stringify({ path: "/var/log/" }));
  assert.equal(pipelines[0].plugin_sources[0].config.directory, "/var/log/");
  const { value: line } = call("emit", JSON.stringify(pipelines), "command");
  assert.match(line, /^lw \\\n {2}--pipeline tail/);
  assert.deepEqual(call("parse", line).value, pipelines);
  assert.deepEqual(call("validate", JSON.stringify(pipelines)).value, pipelines);
  assert.match(call("emit", JSON.stringify(pipelines), "file").value, /^\[\[pipelines\]\]/m);
});

test("a refused call answers why, and the engine keeps answering", () => {
  const refused = [
    [["parse", "lw --nope x"], /not a pipeline flag/],
    [["parse", "lw"], /no pipeline flags/],
    [["parse"], /^usage: lwconf\.parse\(line\)/],
    [["parse", 5], /^usage: /],
    [["preset", "tail", JSON.stringify({ path: "/var/log" })], /path/],
    [["validate", JSON.stringify([{ name: "p" }])], /no sources/],
    [["validate", JSON.stringify(["a", "b"].map((name, i) => ({
      name, plugin_sources: [{ type: "tcp_chain", config: { port: [9000, "x"][i] } }], plugin_sinks: [{ type: "null" }],
    })))], /^pipelines\[1\]\.plugin_sources\[tcp_chain\]\.config\.port: not an integer$/],
    [["emit", JSON.stringify([{ name: "p" }]), "command"], /no sources/],
    [["emit", "[]", "yaml"], /no form "yaml"/],
  ];
  for (const [args, want] of refused) {
    const got = call(...args);
    assert.equal(got.value, undefined, `${args}`);
    assert.match(got.error, want, `${args}`);
  }
  assert.ok(call("schema").value.sources.length > 0);
});
