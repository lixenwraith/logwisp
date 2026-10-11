// LogWisp's configuration engine for a page: one dependency-free ES module
// beside lwconf.wasm, which make wasm writes with it. It knows the engine's
// calls and the shapes of its schema and pipelines, never a plugin, a key or
// a rule, so the page draws whatever the engine it loads describes.

// load starts the engine: the toolchain's wasm_exec.js by a script element
// (outside a page the caller imports it first), the module fetched with its
// integrity, then its main, which sets globalThis.lwconf
export async function load({ execURL, execSRI, wasmURL, wasmSRI }) {
  if (!globalThis.Go) await script(execURL, execSRI);
  const go = new globalThis.Go();
  const fetched = async () => {
    const res = await fetch(wasmURL, { integrity: wasmSRI });
    if (!res.ok) throw new Error(`${wasmURL}: ${res.status}`);
    return res;
  };
  const { instance } = await WebAssembly.instantiateStreaming(fetched(), go.importObject)
    .catch(async () => WebAssembly.instantiate(await (await fetched()).arrayBuffer(), go.importObject)); // a server's wrong type
  go.run(instance);
  if (!globalThis.lwconf) throw new Error("lwconf.wasm did not start");
  return new Engine(globalThis.lwconf);
}

function script(src, integrity) {
  return new Promise((resolve, reject) => {
    const s = Object.assign(document.createElement("script"), { src, onload: resolve });
    s.onerror = () => reject(new Error(`${src} did not load`));
    if (integrity) s.integrity = integrity;
    document.head.append(s);
  });
}

// Engine's calls take objects or JSON text and return the engine's answer,
// {value} or {error, path?, pipeline?, node?, key?}; dirs answers whether a
// preset path is a directory, {"/var/log/app.log": false}
export class Engine {
  #api;
  constructor(api) { this.#api = api; }
  #call(name, ...args) {
    return JSON.parse(this.#api[name](...args.map(a => (typeof a === "string" ? a : JSON.stringify(a)))));
  }
  schema() { return this.#call("schema"); }
  preset(name, values, dirs = {}) { return this.#call("preset", name, values, dirs); }
  parse(text, form, dirs = {}) { return this.#call("parse", text, form, dirs); }
  validate(pipelines) { return this.#call("validate", pipelines); }
  emit(pipelines, form) { return this.#call("emit", pipelines, form); }
  edit(pipelines, op) { return this.#call("edit", pipelines, op); }
}

// fields are the rows a form draws for a node, by its role (and a source's
// or sink's type): a value row a key, with what leaving it unset means, and a
// group a table, holding its own rows; paths are dotted as edit takes them
export function fields(schema, role, type) {
  const plugin = schema[`${role}s`]?.find(p => p.type === type);
  const rows = (keys, prefix) => keys.map(key => {
    const path = prefix + key.key;
    if (Array.isArray(key.keys)) return { path, key, rows: rows(key.keys, path + ".") };
    return { path, key, placeholder: key.default ?? (key.zero ? `(${key.zero})` : (key.hint ?? "")) };
  });
  return rows(plugin?.keys ?? schema.flow.find(s => s.key === role)?.keys ?? [], "");
}

// value is a node's value at a dotted path, undefined while unset; a node is
// {role, id, index} as the engine returns it, a list stage's by its index
export function value(pipelines, pipeline, node, path = "") {
  const p = pipelines[pipeline];
  const list = { source: p?.plugin_sources, sink: p?.plugin_sinks }[node.role];
  const stage = p?.flow?.[node.role];
  let v = list ? list.find(s => s.id === node.id)?.config : Array.isArray(stage) ? stage[node.index] : stage;
  for (const part of path ? path.split(".") : []) v = v?.[part];
  return v;
}

// at names where problems lie: a pipeline's node, however value takes it, the
// pipeline, or nowhere
export function at(pipeline, node) {
  if (pipeline === undefined) return "";
  return node ? `${pipeline}/${node.role}/${node.id ?? ""}/${node.index ?? 0}` : `${pipeline}`;
}

// group sorts validate's problems by at(pipeline, node), then by key, "" for
// the node or pipeline itself
export function group(problems) {
  const out = new Map();
  for (const p of problems) {
    const keys = out.get(at(p.pipeline, p.node)) ?? new Map();
    keys.set(p.key ?? "", [...(keys.get(p.key ?? "") ?? []), p]);
    out.set(at(p.pipeline, p.node), keys);
  }
  return out;
}
