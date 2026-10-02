import { login } from "./scram.js";

const base = new URL("..", location.href);
const form = document.getElementById("login");
const button = form.querySelector("button");
const progress = document.getElementById("progress");
const status = document.getElementById("status");

// Same origin only: an open redirect would lend this page to phishing
function nextTarget() {
  const next = new URLSearchParams(location.search).get("next");
  if (!next) return null;
  try {
    const url = new URL(next, location.href);
    return url.origin === location.origin ? url : null;
  } catch {
    return null;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = new FormData(form);
  button.disabled = true;
  progress.removeAttribute("value");
  progress.hidden = false;
  status.textContent = "Deriving the key, this takes a few seconds…";
  try {
    const session = await login(base, fields.get("username"), fields.get("password"), {
      onProgress: (fraction) => { progress.value = fraction; },
    });
    form.elements.password.value = "";
    const target = nextTarget();
    if (target) {
      location.replace(target.href);
      return;
    }
    status.textContent = `Signed in as ${session.username}.`;
  } catch (err) {
    status.textContent = err.message;
  } finally {
    progress.hidden = true;
    button.disabled = false;
  }
});

// Enabled only once this script runs, so a failed load cannot submit the form natively
button.disabled = false;
