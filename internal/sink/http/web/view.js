import { logout } from "./scram.js";

const base = new URL("..", location.href);
// The server writes its status path here, relative to the mount
const statusPath = document.querySelector('meta[name="logwisp-status"]').content;
const MAX_LINES = 5000;
const log = document.getElementById("log");
const state = document.getElementById("state");
let source = null;

function append(line) {
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
  const row = document.createElement("div");
  row.textContent = line;
  log.append(row);
  while (log.childElementCount > MAX_LINES) log.firstElementChild.remove();
  if (atBottom) log.scrollTop = log.scrollHeight;
}

// The status answer names the stream path; its 401 is the only way to tell an
// expired session apart, since EventSource hides the status of a failure.
async function connect() {
  let res;
  try {
    res = await fetch(new URL("./" + statusPath, base), { credentials: "same-origin", cache: "no-store", redirect: "error" });
  } catch {
    return retry("server unreachable");
  }
  if (res.status === 401) {
    location.replace(new URL("login?next=view", location.href).href);
    return;
  }
  const path = res.ok ? (await res.json().catch(() => ({})))?.endpoints?.stream : null;
  if (typeof path !== "string" || !path.startsWith("/")) {
    return retry(`status unavailable (${res.status})`);
  }
  // Stream paths are absolute in logwisp; the proxy may mount it under a prefix
  source = new EventSource(new URL("./" + path.replace(/^\/+/, ""), base));
  source.addEventListener("connected", () => { state.textContent = "live"; });
  source.addEventListener("disconnect", () => {
    source.close();
    retry("server shut down");
  });
  source.onmessage = (event) => event.data.split("\n").forEach(append);
  source.onerror = () => {
    if (source.readyState === EventSource.CLOSED) retry("disconnected");
    else state.textContent = "reconnecting…";
  };
}

function retry(reason) {
  state.textContent = `${reason}, retrying…`;
  setTimeout(connect, 5000);
}

document.getElementById("logout").addEventListener("click", async () => {
  source?.close();
  try {
    await logout(base);
  } catch (err) {
    state.textContent = err.message;
    return;
  }
  location.replace(new URL("login", location.href).href);
});

connect();
