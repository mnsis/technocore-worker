import { generateWallet } from "./wallet.js";

let wallet = null;
let phraseSaved = false;
let feedbackTimer = null;
const byId = (id) => document.getElementById(id);

async function copyText(value) {
  if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(value); return; }
  const input = document.createElement("textarea"); input.value = value; input.readOnly = true; input.className = "sr-only"; document.body.append(input); input.select(); const copied = document.execCommand("copy"); input.remove();
  if (!copied) throw new Error("Clipboard unavailable.");
}

function feedback(target, normal) {
  clearTimeout(feedbackTimer); target.textContent = "Copied ✓"; byId("wallet-feedback").textContent = "Copied to clipboard.";
  feedbackTimer = setTimeout(() => { target.textContent = normal; byId("wallet-feedback").textContent = ""; }, 2200);
}

function concealPhrase() {
  byId("wallet-reveal-confirm").hidden = true; byId("wallet-phrase").hidden = true; byId("wallet-phrase-list").replaceChildren(); byId("wallet-reveal").hidden = false; byId("wallet-visibility").textContent = "Hidden"; byId("wallet-acknowledge").checked = false; byId("wallet-confirm-reveal").disabled = true;
}

function renderWallet() {
  byId("wallet-empty").hidden = true; byId("wallet-ready").hidden = false; byId("wallet-address").textContent = wallet.address;
  phraseSaved = false; byId("wallet-saved-state").hidden = true; concealPhrase();
}

function renderPhrase() {
  byId("wallet-phrase-list").replaceChildren();
  for (const [index, word] of wallet.mnemonic.split(" ").entries()) { const item = document.createElement("li"); const number = document.createElement("span"); number.textContent = String(index + 1); const value = document.createElement("strong"); value.textContent = word; item.append(number, value); byId("wallet-phrase-list").append(item); }
}

function createWallet() {
  try { wallet = generateWallet(); renderWallet(); byId("wallet-status").textContent = "Wallet created locally."; }
  catch { byId("wallet-status").textContent = "Wallet generation is unavailable in this browser."; }
}

byId("wallet-create").addEventListener("click", createWallet);
byId("wallet-copy-address").addEventListener("click", async () => { if (!wallet) return; try { await copyText(wallet.address); feedback(byId("wallet-copy-address"), "Copy address"); } catch { byId("wallet-feedback").textContent = "Clipboard unavailable."; } });
byId("wallet-reveal").addEventListener("click", () => { if (!wallet) return; byId("wallet-reveal").hidden = true; byId("wallet-reveal-confirm").hidden = false; });
byId("wallet-acknowledge").addEventListener("change", () => { byId("wallet-confirm-reveal").disabled = !byId("wallet-acknowledge").checked; });
byId("wallet-confirm-reveal").addEventListener("click", () => { if (!wallet || !byId("wallet-acknowledge").checked) return; renderPhrase(); byId("wallet-reveal-confirm").hidden = true; byId("wallet-phrase").hidden = false; byId("wallet-visibility").textContent = "Visible"; });
byId("wallet-copy-phrase").addEventListener("click", async () => { if (!wallet || byId("wallet-phrase").hidden) return; try { await copyText(wallet.mnemonic); feedback(byId("wallet-copy-phrase"), "Copy recovery phrase"); } catch { byId("wallet-feedback").textContent = "Clipboard unavailable."; } });
byId("wallet-saved").addEventListener("click", () => { if (!wallet) return; phraseSaved = true; concealPhrase(); byId("wallet-saved-state").hidden = false; byId("wallet-status").textContent = "Recovery phrase marked as saved. This site still does not store it."; });
byId("wallet-create-another").addEventListener("click", () => { if (!wallet) return; const warning = phraseSaved ? "Replace the current in-memory wallet with a new wallet?" : "The current recovery phrase has not been marked as saved. Replace this in-memory wallet anyway?"; if (confirm(warning)) createWallet(); });
addEventListener("pagehide", () => { wallet = null; });
