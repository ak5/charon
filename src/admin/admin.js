'use strict';
const $ = id => document.getElementById(id);
let busy = false;
function decode(value) {
  const bytes = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bytes, c => c.charCodeAt(0));
}
function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function api(path, value) {
  const response = await fetch(`/api/${path}`, value === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value), cache: 'no-store' });
  if (!response.ok) throw new Error(response.status === 429 ? 'Too many attempts. Please wait a minute.' : 'Request failed. Check your credentials and try again.');
  return response.status === 204 ? null : response.json();
}
async function refresh() {
  const state = await api('status');
  $('enrollment').hidden = state.enrolled;
  $('login').hidden = !state.enrolled || state.authenticated;
  $('vault').hidden = !state.authenticated;
  $('unlock-form').hidden = state.unlocked;
  $('lock').hidden = !state.unlocked;
  $('status').textContent = state.unlocked ? 'Vault unlocked' : state.enrolled ? 'Vault locked' : 'Enrollment required';
}
async function register(code) {
  const result = await api('register/start', { code });
  const options = result.options.publicKey;
  options.challenge = decode(options.challenge);
  options.user.id = decode(options.user.id);
  for (const credential of options.excludeCredentials || []) credential.id = decode(credential.id);
  const credential = await navigator.credentials.create({ publicKey: options });
  await api('register/finish', { id: result.id, credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { attestationObject: encode(credential.response.attestationObject), clientDataJSON: encode(credential.response.clientDataJSON), transports: credential.response.getTransports?.() || [] }, extensions: credential.getClientExtensionResults() } });
}
async function login() {
  const result = await api('login/start', {});
  const options = result.options.publicKey;
  options.challenge = decode(options.challenge);
  for (const credential of options.allowCredentials || []) credential.id = decode(credential.id);
  const credential = await navigator.credentials.get({ publicKey: options });
  await api('login/finish', { id: result.id, credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { authenticatorData: encode(credential.response.authenticatorData), clientDataJSON: encode(credential.response.clientDataJSON), signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null }, extensions: credential.getClientExtensionResults() } });
}
async function action(fn) {
  if (busy) return;
  busy = true; $('error').textContent = '';
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try { await fn(); await refresh(); } catch (error) { $('error').textContent = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled or timed out.' : error.message; }
  finally { busy = false; for (const button of document.querySelectorAll('button')) button.disabled = false; }
}
$('enroll-form').addEventListener('submit', event => { event.preventDefault(); const code = $('code').value; $('code').value = ''; action(async () => { await register(code); await login(); }); });
$('sign-in').addEventListener('click', () => action(login));
$('add-passkey').addEventListener('click', () => action(() => register('')));
$('unlock-form').addEventListener('submit', event => { event.preventDefault(); const password = $('password').value; $('password').value = ''; action(() => api('unlock', { password })); });
$('lock').addEventListener('click', () => action(() => api('lock', {})));
$('sign-out').addEventListener('click', () => action(() => api('logout', {})));
refresh().catch(() => { $('status').textContent = 'Unable to reach Charon'; });
