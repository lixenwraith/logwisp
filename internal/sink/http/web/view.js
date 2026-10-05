import { cookiesUsable, login, loginUnavailable, logout, stream } from "./scram.js";

const base = new URL("..", location.href);
// The server writes its status path here, relative to the mount, and "none"
// as the login when the browser needs none: no auth, or its mTLS certificate
const meta = (name) => document.querySelector(`meta[name="logwisp-${name}"]`).content;
const statusPath = meta("status");
const open = meta("login") === "none";
const MAX_LINES = 5000;
const log = document.getElementById("log");
const state = document.getElementById("state");
const signOut = document.getElementById("logout");
const form = document.getElementById("login");
const progress = document.getElementById("progress");
const status = document.getElementById("status");
const search = document.getElementById("search");
const lowest = document.getElementById("level");
// The server's levels by rising severity, each with the words naming it
const levels = JSON.parse(meta("levels"));
const named = new Map(levels.flatMap(({ level, names }) => names.map((name) => [name, level])));
const rank = new Map(levels.map(({ level }, i) => [level, i]));
for (const { level } of levels) lowest.add(new Option(`${level} and above`, level));

// A page without a login needs no WebCrypto, so plain http works too
const unavailable = open ? "" : loginUnavailable();
// Without cookies the session is a token in this variable only: never stored,
// so it ends with the page, or earlier with its lifetime or sign-out
let tokenMode = !open && !unavailable && !cookiesUsable();
let token = null;
// The login page comes back with this fragment: a 401 now means the browser
// dropped the session cookie
let fresh = location.hash === "#signed-in";
if (fresh) history.replaceState(null, "", location.pathname + location.search);
let stopStream = null;
let timer = null;

// An entry's level is its first word naming one, as the server reads a line
function levelOf(text) {
  for (const [word] of text.matchAll(/\w+/g)) {
    const level = named.get(word.toUpperCase());
    if (level) return level;
  }
  return "";
}

// A line shows when it contains the search, in any case, and its entry's level
// reaches the lowest chosen; with none chosen, lines without a level show too
function shown(row) {
  const floor = rank.get(lowest.value);
  if (floor !== undefined && !(rank.get(row.dataset.level) >= floor)) return false;
  const text = search.value.trim().toLowerCase();
  return !text || row.textContent.toLowerCase().includes(text);
}

function refilter() {
  for (const row of log.children) row.hidden = !shown(row);
  log.scrollTop = log.scrollHeight;
}

function append(line, level) {
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
  const row = document.createElement("div");
  row.textContent = line;
  row.dataset.level = level;
  row.hidden = !shown(row);
  log.append(row);
  while (log.childElementCount > MAX_LINES) log.firstElementChild.remove();
  if (atBottom) log.scrollTop = log.scrollHeight;
}

// The status answer names the stream path and whether the stream has room; its
// 401 is the only way to tell an ended session apart, since EventSource hides
// the status of a failure.
async function connect() {
  if (tokenMode && !token) return showLogin("");
  let res;
  try {
    res = await fetch(new URL("./" + statusPath, base), {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      credentials: "same-origin", cache: "no-store", redirect: "error",
    });
  } catch {
    return retry("server unreachable");
  }
  // An open page has no session to end: a 401 there is a proxy's, so it retries
  if (res.status === 401 && !open) return sessionEnded();
  fresh = false;
  const body = res.ok ? await res.json().catch(() => ({})) : {};
  const path = body?.endpoints?.stream;
  if (typeof path !== "string" || !path.startsWith("/")) {
    return retry(`status unavailable (${res.status})`);
  }
  // The stream would answer 503, which EventSource hides
  const { active_clients: active, max_connections: max } = body?.server ?? {};
  if (max > 0 && active >= max) return retry(`server full (${active} of ${max} streams)`);
  // Stream paths are absolute in logwisp; the proxy may mount it under a prefix
  const url = new URL("./" + path.replace(/^\/+/, ""), base);
  if (tokenMode) streamWithToken(url);
  else streamWithCookie(url);
}

function onEvent(type, data) {
  if (type === "connected") state.textContent = "live";
  if (type === "disconnect") {
    stopStream();
    retry("server shut down");
  }
  if (type === "message") {
    const level = levelOf(data);
    for (const line of data.split("\n")) append(line, level);
  }
}

function streamWithCookie(url) {
  const source = new EventSource(url);
  stopStream = () => source.close();
  for (const type of ["connected", "disconnect", "message"]) {
    source.addEventListener(type, (event) => onEvent(type, event.data));
  }
  source.onerror = () => {
    if (source.readyState === EventSource.CLOSED) retry("disconnected");
    else state.textContent = "reconnecting…";
  };
}

async function streamWithToken(url) {
  const abort = new AbortController();
  stopStream = () => abort.abort();
  let refused = 0;
  try {
    await stream(url, { token, signal: abort.signal, onEvent: (event) => onEvent(event.type, event.data) });
  } catch (err) {
    refused = err.status ?? 0;
  }
  if (abort.signal.aborted) return;
  if (refused === 401) sessionEnded();
  else retry(refused ? `stream refused (${refused})` : "disconnected");
}

function sessionEnded() {
  if (!tokenMode && !fresh) {
    location.replace(new URL("login?next=" + encodeURIComponent("view#signed-in"), location.href).href);
    return;
  }
  const expired = token !== null;
  tokenMode = true;
  token = null;
  showLogin(expired ? "The session ended; sign in again." : "");
}

function showLogin(message) {
  stopStream?.();
  clearTimeout(timer);
  state.textContent = "signed out";
  signOut.hidden = true;
  status.textContent = message;
  form.hidden = false;
  form.elements.username.focus();
}

function retry(reason) {
  state.textContent = `${reason}, retrying…`;
  clearTimeout(timer);
  timer = setTimeout(connect, 5000);
}

search.addEventListener("input", refilter);
lowest.addEventListener("change", refilter);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = new FormData(form);
  const button = form.querySelector("button");
  button.disabled = true;
  progress.removeAttribute("value");
  progress.hidden = false;
  status.textContent = "Deriving the key, this takes a few seconds…";
  try {
    ({ token } = await login(base, fields.get("username"), fields.get("password"), {
      session: "token",
      onProgress: (fraction) => { progress.value = fraction; },
    }));
  } catch (err) {
    status.textContent = err.message;
    return;
  } finally {
    progress.hidden = true;
    button.disabled = false;
  }
  form.elements.password.value = "";
  form.hidden = true;
  signOut.hidden = false;
  state.textContent = "connecting…";
  connect();
});

signOut.addEventListener("click", async () => {
  stopStream?.();
  clearTimeout(timer);
  try {
    await logout(base, { token });
  } catch (err) {
    state.textContent = err.message;
    return;
  }
  if (!tokenMode) {
    location.replace(new URL("login", location.href).href);
    return;
  }
  token = null;
  showLogin("Signed out.");
});

// No session of either kind can start on this page, so it offers no form
if (unavailable) {
  state.textContent = unavailable;
  signOut.hidden = true;
} else {
  signOut.hidden = open;
  connect();
}
