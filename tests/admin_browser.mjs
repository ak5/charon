// Real Chrome UI/WebAuthn proof, invoked only by the synthetic Rust fixture.
import { readFileSync, writeFileSync } from 'node:fs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const socket = new WebSocket(input.devtools);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let nextId = 1;
let failedPath = "";
const pending = new Map();
socket.onmessage = event => {
  const message = JSON.parse(event.data);
  if (message.method === "Network.responseReceived" && message.params.response.status >= 400 && message.params.response.url.startsWith(input.origin + "/api/")) failedPath = new URL(message.params.response.url).pathname + " (" + message.params.response.status + ")";
  const waiter = pending.get(message.id);
  if (!waiter) return;
  pending.delete(message.id);
  if (message.error) waiter.reject(new Error('Chrome protocol request failed'));
  else waiter.resolve(message.result);
};
function command(method, params = {}, sessionId) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('Chrome protocol timeout')); }, 15000);
    pending.set(id, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
const cdp = (method, params) => command(method, params, sessionId);
await cdp('Page.enable');
await cdp('Network.enable');
await cdp('WebAuthn.enable');
await cdp('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
await cdp('Page.navigate', { url: input.origin });
async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error('Admin page evaluation failed');
  return result.result.value;
}
async function waitFor(expression) {
  for (let i = 0; i < 150; i++) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  const error = await evaluate("document.getElementById('error')?.textContent || ''");
  throw new Error(`Admin UI did not reach expected state${error ? ': ' + error : ''} ${failedPath}`);
}
await waitFor("document.getElementById('enrollment') && !document.getElementById('enrollment').hidden");
await evaluate(`document.getElementById('code').value = ${JSON.stringify(input.code)}; document.querySelector('#enroll-form button').click()`);
await waitFor("!document.getElementById('vault').hidden && document.getElementById('status').textContent === 'Vault locked'");
await evaluate(`document.getElementById('password').value = ${JSON.stringify(input.password)}; document.querySelector('#unlock-form button').click()`);
await waitFor("document.getElementById('status').textContent === 'Vault unlocked'");
if (!await evaluate("document.getElementById('password').value === '' && document.getElementById('code').value === ''")) throw new Error('Admin UI retained secret input');
await evaluate("document.getElementById('lock').click()");
await waitFor("document.getElementById('status').textContent === 'Vault locked' && !document.getElementById('lock').disabled");
await evaluate("document.getElementById('sign-out').click()");
await waitFor("!document.getElementById('login').hidden && !document.getElementById('sign-in').disabled");
await evaluate("document.getElementById('sign-in').click()");
await waitFor("!document.getElementById('vault').hidden && !document.getElementById('sign-out').disabled");
if (input.screenshot) {
  await cdp('Emulation.setDeviceMetricsOverride', { width: 1000, height: 900, deviceScaleFactor: 1, mobile: false });
  const screenshot = await cdp('Page.captureScreenshot', { format: 'png' });
  writeFileSync(input.screenshot, Buffer.from(screenshot.data, 'base64'));
}
await command('Target.closeTarget', { targetId });
socket.close();
console.log('Chrome passkey enrollment, sign-in, unlock, lock, and sign-out passed');
