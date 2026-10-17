'use strict';
/**
 * ESCROW X — Email Service v3 (branded templates)
 *
 * - Sends through the Gmail API (OAuth refresh token), same as before.
 * - Same endpoints as before: GET /health, GET /oauth/start, GET /oauth/callback,
 *   POST /send-verification, POST /send-email  (the marketplace needs NO change to keep working).
 * - NEW: every email is rendered server-side with one professional template, chosen from
 *   `type` / `policyKey` (or detected from the subject for old clients). The client-supplied
 *   `html` is no longer injected into the message (it caused dark-on-dark text and is an
 *   HTML-injection vector); the `text` is used as the content instead.
 * - NEW: the logo is hosted by this service (GET /assets/logo.png) and referenced by URL, so
 *   the email no longer carries the logo as an attachment.
 * - NEW: basic abuse protection (per-IP and per-recipient rate limit, optional origin allow-list).
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 10000);
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim()).filter(Boolean);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'escrowx.verifier@gmail.com';
const BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://escrowx-email-service.onrender.com').replace(/\/$/, '');
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, ''); // optional: link shown in the footer
const REDIRECT_URI = `${BASE_URL}/oauth/callback`;
const LOGO_URL = `${BASE_URL}/assets/logo.png`;
const LOGO_PATH = path.join(__dirname, 'escrowx-logo-email.png');
const ENABLE_PREVIEW = process.env.ENABLE_PREVIEW === '1';
const EMAIL_API_KEY = process.env.EMAIL_API_KEY || ''; // when set, /send-email and /send-verification require 'Authorization: Bearer <key>'
const RATE_IP_MAX = Number(process.env.RATE_IP_MAX || 40);          // per 10 min
const RATE_TO_MAX = Number(process.env.RATE_RECIPIENT_MAX || 15);    // per 10 min
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const oauthStates = new Map();

/* ------------------------------------------------------------------ helpers */
function corsHeaders(req) {
  const origin = req && req.headers ? req.headers.origin : '';
  let allow = '*';
  if (!ALLOWED_ORIGINS.includes('*')) allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST,GET,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin'
  };
}
function sendJson(req, res, status, data) {
  res.writeHead(status, { ...corsHeaders(req), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(html);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 100000) { reject(new Error('Request body too large.')); req.destroy(); }
    });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
const validEmail = v => /^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$/.test(String(v || '').trim());
const b64url = v => Buffer.from(v).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const hits = new Map(); // key -> [timestamps]
function rateLimited(key, max) {
  const now = Date.now(), windowMs = 10 * 60 * 1000;
  const list = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (list.length >= max) { hits.set(key, list); return true; }
  list.push(now); hits.set(key, list);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < windowMs)) hits.delete(k);
  return false;
}

/* ---------------------------------------------------------------- templates */
const C = { bg: '#eef2f8', card: '#ffffff', cardAlt: '#f1f6ff', line: '#d6e0f0', blue: '#1a7bff', cyan: '#0a66d6', text: '#0b1b3a', muted: '#475874', faint: '#7a8aa8', ok: '#0f9d6a', warn: '#d98a00' }; // light theme

const TYPES = {
  verification:     { title: 'Verify your email',                 intro: 'Use this code to verify your account on EscrowX Marketplace.', kind: 'code',   warn: 'Never share this code with anyone. The EscrowX team will never ask for it.', preheader: 'Your EscrowX verification code' },
  login_code:       { title: 'Sign-in code',                      intro: 'Enter this code to finish signing in to your account.',           kind: 'code',   warn: 'If this was not you, change your password immediately.', preheader: 'Your EscrowX sign-in code' },
  password_recovery:{ title: 'Password recovery',                 intro: 'We received a request to reset your password. Use this code to continue.', kind: 'code', warn: 'If you did not request this, ignore this message: your current password is still valid.', preheader: 'Code to reset your password' },
  admin_recovery:   { title: 'Administrator access recovery',     intro: 'Use this code to set a new administrator password.',              kind: 'code',   warn: 'If you did not request this, review the security of the administrator account.', preheader: 'Administrator recovery code' },
  withdrawal_code:  { title: 'Confirm your withdrawal',           intro: 'Use this code to authorize your withdrawal request.',              kind: 'code',   warn: 'If you did not request a withdrawal, secure your account immediately and contact support.', preheader: 'Code to confirm your withdrawal' },
  login_alert:      { title: 'New sign-in detected',              intro: 'Your EscrowX account was just signed in to.',                      kind: 'notice', warn: 'If this was not you, change your password immediately and contact support.', preheader: 'New sign-in to your account' },
  deposit:          { title: 'Deposit credited',                  intro: 'Your deposit was verified on the blockchain and credited to your balance.', kind: 'details', warn: '', preheader: 'Your deposit was credited' },
  withdrawal_done:  { title: 'Withdrawal completed',              intro: 'Your withdrawal was processed and sent to the blockchain.',        kind: 'details', warn: '', preheader: 'Your withdrawal was completed' },
  order:            { title: 'P2P order update',                  intro: '',                                                                 kind: 'notice', warn: '', preheader: 'An update on your P2P order' },
  support:          { title: 'Support reply',                     intro: '',                                                                 kind: 'notice', warn: '', preheader: 'Support replied to your request' },
  generic:          { title: 'EscrowX notification',              intro: '',                                                                 kind: 'notice', warn: '', preheader: 'EscrowX notification' }
};

const POLICY_TO_TYPE = {
  REGISTRATION_AUTH: 'verification', LOGIN_AUTHENTICATION: 'login_code', PASSWORD_RECOVERY: 'password_recovery',
  ADMIN_PASSWORD_RECOVERY: 'admin_recovery', WITHDRAWAL_OTP: 'withdrawal_code', DEPOSIT_CONFIRMATION: 'deposit',
  WITHDRAWAL_COMPLETED: 'withdrawal_done', P2P_ORDER: 'order', SUPPORT_RESPONSE: 'support'
};

function detectType(body, subject, text) {
  const explicit = String(body.type || '').toLowerCase();
  if (TYPES[explicit]) return explicit;
  const pol = POLICY_TO_TYPE[String(body.policyKey || '').toUpperCase()];
  const s = `${subject} ${text}`.toLowerCase();
  // The marketplace uses one policyKey for several login-related mails, so refine by wording.
  if (/withdrawal verification|withdrawal code|código de retiro/.test(s)) return 'withdrawal_code';
  if (/admin(istrator)?.*(recovery|password)|recuperaci[oó]n.*administrador/.test(s)) return 'admin_recovery';
  if (/password recovery|recovery code|reset.*password|recuperaci[oó]n de contrase/.test(s)) return 'password_recovery';
  if (/2fa|two-factor|dos factores/.test(s)) return 'login_code';
  if (/verification code|verify your email|verifica|new verification code/.test(s)) return 'verification';
  if (/withdrawal.*(completed|processed|sent)|retiro.*(completado|procesado)/.test(s)) return 'withdrawal_done';
  if (/deposit.*(verified|credited|confirmed)|dep[oó]sito.*(acreditado|verificado)/.test(s)) return 'deposit';
  if (/new sign-in|sign-in detected|nuevo inicio/.test(s)) return 'login_alert';
  if (pol) return pol;
  return 'generic';
}

function cleanBodyText(text) {
  return String(text || '')
    .replace(/^\s*ESCROW X( P2P)?\s*\n+/i, '')
    .replace(/\n*\s*This is an automated notification from ESCROW X P2P\.?\s*$/i, '')
    .trim();
}
function pick(text, re) { const m = String(text).match(re); return m ? m[1] : ''; }

function parseFacts(type, text) {
  const facts = [];
  const account = pick(text, /Account:\s*([^\s]+@[^\s]+)/i);
  if (account) facts.push(['Account', account]);
  const time = pick(text, /Time:\s*([0-9T:.\-Z+]+)/i);
  if (time) facts.push(['Time', time.replace('T', ' ').replace(/\.\d+Z?$/, ' UTC').replace(/Z$/, ' UTC')]);
  const amt = text.match(/of\s+([0-9][0-9.,]*)\s+([A-Z]{2,6})\b/);
  if (amt) { facts.push(['Amount', `${amt[1]} ${amt[2]}`]); }
  const tx = pick(text, /(0x[a-fA-F0-9]{64})/);
  if (tx) facts.push(['Transaction', `${tx.slice(0, 10)}…${tx.slice(-8)}`]);
  return facts;
}

function codeBlock(code) {
  const spaced = esc(code); // no real spaces between digits: the code must copy and paste as one clean number
  return `<tr><td align="center" style="padding:8px 28px 6px"><table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto"><tr><td align="center" bgcolor="${C.cardAlt}" style="background:${C.cardAlt};border:1px solid ${C.blue};border-radius:14px;padding:18px 26px;font-family:'Courier New',Consolas,monospace;font-size:36px;line-height:1;font-weight:700;letter-spacing:4px;color:${C.text}">${spaced}</td></tr></table></td></tr>`;
}
function factsBlock(facts) {
  if (!facts.length) return '';
  const rows = facts.map(([k, v], i) => `<tr><td style="padding:10px 14px;font-size:13px;color:${C.muted};${i ? `border-top:1px solid ${C.line};` : ''}">${esc(k)}</td><td align="right" style="padding:10px 14px;font-size:14px;font-weight:600;color:${C.text};${i ? `border-top:1px solid ${C.line};` : ''}word-break:break-all">${esc(v)}</td></tr>`).join('');
  return `<tr><td style="padding:6px 28px 4px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${C.cardAlt}" style="background:${C.cardAlt};border:1px solid ${C.line};border-radius:12px">${rows}</table></td></tr>`;
}
function paragraphs(text) {
  return String(text).split(/\n{2,}/).map(p => p.trim()).filter(Boolean)
    .map(p => `<tr><td style="padding:0 28px 12px;font-size:15px;line-height:1.65;color:${C.text}">${esc(p).replace(/\n/g, '<br>')}</td></tr>`).join('');
}

function renderEmail({ type, subject, text, code }) {
  const def = TYPES[type] || TYPES.generic;
  const body = cleanBodyText(text);
  const expiry = pick(body, /(\d+)\s*minutes?/i);
  const facts = parseFacts(type, body);
  let content = '';
  let plain = '';

  if (def.kind === 'code' && code) {
    content += `<tr><td style="padding:0 28px 14px;font-size:15px;line-height:1.65;color:${C.text}">${esc(def.intro)}</td></tr>`;
    content += codeBlock(code);
    content += `<tr><td align="center" style="padding:12px 28px 4px;font-size:13px;color:${C.muted}">${expiry ? `This code expires in <strong style="color:${C.text}">${esc(expiry)} minutes</strong>.` : 'This code expires in a few minutes.'}</td></tr>`;
    plain = `${def.title}\n\n${def.intro}\n\nCode: ${code}\n${expiry ? `Expires in ${expiry} minutes.\n` : ''}\n${def.warn}`;
  } else if (type === 'login_alert') {
    content += `<tr><td style="padding:0 28px 14px;font-size:15px;line-height:1.65;color:${C.text}">${esc(def.intro)}</td></tr>`;
    content += factsBlock(facts.length ? facts : []);
    if (!facts.length) content += paragraphs(body);
    plain = `${def.title}\n\n${def.intro}\n${facts.map(f => `${f[0]}: ${f[1]}`).join('\n')}\n\n${def.warn}`;
  } else if (def.kind === 'details') {
    content += `<tr><td style="padding:0 28px 14px;font-size:15px;line-height:1.65;color:${C.text}">${esc(def.intro)}</td></tr>`;
    content += facts.length ? factsBlock(facts) : paragraphs(body);
    plain = `${def.title}\n\n${def.intro}\n${facts.map(f => `${f[0]}: ${f[1]}`).join('\n')}${facts.length ? '' : body}`;
  } else {
    if (def.intro) content += `<tr><td style="padding:0 28px 12px;font-size:15px;line-height:1.65;color:${C.text}">${esc(def.intro)}</td></tr>`;
    content += paragraphs(body || subject);
    plain = `${def.title}\n\n${body || subject}`;
  }

  if (def.warn) {
    content += `<tr><td style="padding:14px 28px 4px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="border-left:3px solid ${C.warn};padding:6px 0 6px 12px;font-size:13px;line-height:1.6;color:${C.muted}">${esc(def.warn)}</td></tr></table></td></tr>`;
  }

  const footerLink = APP_URL ? ` · <a href="${esc(APP_URL)}" style="color:${C.cyan};text-decoration:none">${esc(APP_URL.replace(/^https?:\/\//, ''))}</a>` : '';
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${esc(subject || def.title)}</title></head>
<body style="margin:0;padding:0;background:${C.bg};-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${esc(def.preheader)}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${C.bg}" style="background:${C.bg}"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${C.card}" style="max-width:560px;background:${C.card};border:1px solid ${C.line};border-radius:18px;overflow:hidden;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif">
<tr><td align="center" style="padding:26px 24px 18px;border-bottom:1px solid ${C.line}"><img src="${LOGO_URL}" width="168" alt="EscrowX Marketplace" style="display:block;width:168px;max-width:70%;height:auto;border:0;border-radius:14px"></td></tr>
<tr><td align="center" style="padding:26px 28px 6px;font-size:22px;line-height:1.3;font-weight:700;color:${C.text}">${esc(def.title)}</td></tr>
<tr><td style="padding:6px 0 0"></td></tr>
${content}
<tr><td style="padding:22px 28px 0"><div style="border-top:1px solid ${C.line}"></div></td></tr>
<tr><td align="center" style="padding:16px 28px 6px;font-size:11px;letter-spacing:2px;color:${C.cyan}">SECURE&nbsp;·&nbsp;RELIABLE&nbsp;·&nbsp;FAST</td></tr>
<tr><td align="center" style="padding:6px 28px 26px;font-size:12px;line-height:1.6;color:${C.faint}">Automated security message from EscrowX Marketplace. Please do not reply to this email.${footerLink}</td></tr>
</table></td></tr></table></body></html>`;
  return { html, text: `${plain}\n\n— EscrowX Marketplace`.trim() };
}

/* -------------------------------------------------------------------- Gmail */
async function getAccessToken() {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) {
    throw new Error('Gmail is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REFRESH_TOKEN in the service environment.');
  }
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, refresh_token: GOOGLE_REFRESH_TOKEN, grant_type: 'refresh_token' })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(`Google token refresh failed: ${data.error_description || data.error || `HTTP ${response.status}`}`);
  return data.access_token;
}

async function sendGmail({ to, subject, text, html }) {
  const accessToken = await getAccessToken();
  const boundary = `escrowx_${crypto.randomBytes(12).toString('hex')}`;
  const encodedSubject = `=?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`;
  const mime = [
    `From: EscrowX <${FROM_EMAIL}>`, `To: ${to}`, 'Auto-Submitted: auto-generated', 'Content-Language: en', `Subject: ${encodedSubject}`, 'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`, '',
    `--${boundary}`, 'Content-Type: text/plain; charset="UTF-8"', 'Content-Transfer-Encoding: base64', '', Buffer.from(text, 'utf8').toString('base64'),
    `--${boundary}`, 'Content-Type: text/html; charset="UTF-8"', 'Content-Transfer-Encoding: base64', '', Buffer.from(html, 'utf8').toString('base64'),
    `--${boundary}--`, ''
  ].join('\r\n');
  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ raw: b64url(mime) })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Gmail send failed: ${data.error?.message || `HTTP ${response.status}`}`);
  return data;
}

/* ------------------------------------------------------------------- server */
const SAMPLES = {
  verification: { subject: 'ESCROW X — Verification code', text: 'Your ESCROW X verification code is 727374. It expires in 10 minutes.' },
  login_code: { subject: 'ESCROW X — Your 2FA sign-in code', text: 'Your ESCROW X 2FA sign-in code is 481920. It expires in 10 minutes.' },
  login_alert: { subject: 'ESCROW X — New sign-in', text: 'Your ESCROW X account was just signed in to.\n\nAccount: user@example.com\nTime: 2026-10-16T03:15:38.933Z\n\nIf you did not initiate this sign-in, secure your account immediately.' },
  password_recovery: { subject: 'ESCROW X — Password recovery code', text: 'Your ESCROW X password recovery code is 305771. It expires in 10 minutes.' },
  admin_recovery: { subject: 'ESCROW X — Administrator password recovery code', text: 'Your administrator password recovery code is 118204. It expires in 10 minutes.' },
  withdrawal_code: { subject: 'ESCROW X — Withdrawal verification code', text: 'Your ESCROW X withdrawal verification code is 649013. It expires in 10 minutes.' },
  deposit: { subject: 'ESCROW X — RBL deposit verified', text: 'Your RBL deposit of 250 RBL was verified successfully on the Rubi blockchain and credited to your ESCROW X balance. Transaction: 0x' + 'ab12'.repeat(16) + '.' },
  withdrawal_done: { subject: 'ESCROW X — Withdrawal completed', text: 'Your withdrawal of 100 USDT was completed. Transaction: 0x' + 'cd34'.repeat(16) + '.' },
  order: { subject: 'ESCROW X — P2P order notification', text: 'Your P2P order was completed: you bought 50 RBL.' },
  support: { subject: 'ESCROW X — Support notification', text: 'Our team replied to your ticket. Open the app to read the full answer.' }
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (req.method === 'OPTIONS') { res.writeHead(204, { ...corsHeaders(req), 'Cache-Control': 'no-store' }); return res.end(); }

  if (req.method === 'GET' && url.pathname === '/health') {
    const configured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REFRESH_TOKEN);
    return sendJson(req, res, 200, { ok: true, service: 'ESCROW X P2P Email Service', version: '3.0.0', provider: 'Gmail API', configured, from: FROM_EMAIL, oauthRedirectUri: REDIRECT_URI, templates: Object.keys(TYPES) });
  }

  if (req.method === 'GET' && url.pathname === '/assets/logo.png') {
    try {
      const png = fs.readFileSync(LOGO_PATH);
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400', 'Access-Control-Allow-Origin': '*' });
      return res.end(png);
    } catch { return sendJson(req, res, 404, { ok: false, error: 'Logo not found.' }); }
  }

  if (req.method === 'GET' && ENABLE_PREVIEW && url.pathname.startsWith('/preview')) {
    const type = url.pathname.split('/')[2] || '';
    if (!SAMPLES[type]) return sendHtml(res, 200, `<body style="font-family:Arial;background:#050914;color:#eef5ff;padding:24px"><h3>Preview</h3>${Object.keys(SAMPLES).map(t => `<p><a style="color:#4fd1ff" href="/preview/${t}">${t}</a></p>`).join('')}</body>`);
    const s = SAMPLES[type];
    const code = (s.text.match(/\b(\d{6})\b/) || [])[1] || '';
    return sendHtml(res, 200, renderEmail({ type, subject: s.subject, text: s.text, code }).html);
  }

  if (req.method === 'GET' && url.pathname === '/oauth/start') {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return sendJson(req, res, 503, { ok: false, error: 'Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render before starting OAuth.' });
    const state = crypto.randomBytes(24).toString('hex');
    oauthStates.set(state, Date.now() + OAUTH_STATE_TTL_MS);
    for (const [key, expiry] of oauthStates) if (expiry < Date.now()) oauthStates.delete(key);
    const params = new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code', scope: 'https://www.googleapis.com/auth/gmail.send', access_type: 'offline', prompt: 'consent', state });
    res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`, 'Cache-Control': 'no-store' });
    return res.end();
  }

  if (req.method === 'GET' && url.pathname === '/oauth/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (url.searchParams.get('error')) return sendHtml(res, 400, '<h2>Authorization cancelled</h2><p>Start again from /oauth/start.</p>');
    if (!state || !oauthStates.has(state) || oauthStates.get(state) < Date.now()) return sendHtml(res, 400, '<h2>Request expired or invalid</h2><p>Start again from /oauth/start.</p>');
    oauthStates.delete(state);
    if (!code) return sendHtml(res, 400, '<h2>Missing authorization code</h2>');
    try {
      const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code' }) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error_description || data.error || `HTTP ${response.status}`);
      if (!data.refresh_token) throw new Error('Google did not return a refresh token. Revoke this app access from your Google Account and restart OAuth with consent.');
      return sendHtml(res, 200, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>EscrowX OAuth</title><body style="font-family:Arial;background:#081225;color:#fff;padding:24px;max-width:760px;margin:auto"><h2>Gmail authorization completed</h2><p>Copy this refresh token and save it directly as the <b>GOOGLE_REFRESH_TOKEN</b> variable in Render. Do not share it in chat or publish it.</p><textarea readonly style="width:100%;height:130px;word-break:break-all">${esc(data.refresh_token)}</textarea><p>For security, this page does not store the token on the server.</p></body></html>`);
    } catch (e) {
      console.error(JSON.stringify({ event: 'oauth_callback_error', error: e.message }));
      return sendHtml(res, 400, `<h2>OAuth could not be completed</h2><p>${esc(e.message)}</p>`);
    }
  }

  if (req.method === 'POST' && (url.pathname === '/send-verification' || url.pathname === '/send-email')) {
    const requestId = `email_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    try {
      if (!ALLOWED_ORIGINS.includes('*') && req.headers.origin && !ALLOWED_ORIGINS.includes(req.headers.origin)) {
        return sendJson(req, res, 403, { ok: false, error: 'Origin not allowed.', requestId });
      }
      let trusted = false; // the platform API (authenticated with EMAIL_API_KEY) has its own per-user limits
      if (EMAIL_API_KEY) {
        const sent = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
        const ha = crypto.createHash('sha256').update(sent).digest(), hb = crypto.createHash('sha256').update(EMAIL_API_KEY).digest();
        if (!crypto.timingSafeEqual(ha, hb)) return sendJson(req, res, 401, { ok: false, error: 'Unauthorized.', requestId });
        trusted = true;
      }
      if (!trusted && rateLimited(`ip:${ip}`, RATE_IP_MAX)) return sendJson(req, res, 429, { ok: false, error: 'Too many requests. Try again later.', requestId });
      const body = await readBody(req);
      const to = String(body.to || '').trim();
      if (!validEmail(to)) return sendJson(req, res, 400, { ok: false, error: 'Invalid recipient email.', requestId });
      if (rateLimited(`to:${to.toLowerCase()}`, RATE_TO_MAX)) return sendJson(req, res, 429, { ok: false, error: 'Too many emails to this address. Try again later.', requestId });

      let subject, type, code = '', text = '';
      if (url.pathname === '/send-verification') {
        code = String(body.code || '').trim();
        if (!/^\d{6}$/.test(code)) return sendJson(req, res, 400, { ok: false, error: 'Verification code must be 6 digits.', requestId });
        subject = String(body.subject || 'EscrowX — Verification code').trim();
        type = TYPES[String(body.type || '')] ? String(body.type) : 'verification';
        text = `Your code is ${code}. It expires in 15 minutes.`;
      } else {
        text = String(body.text || '').trim();
        subject = String(body.subject || 'EscrowX Marketplace notification').trim();
        if (!subject || !text) return sendJson(req, res, 400, { ok: false, error: 'Subject and text are required.', requestId });
        if (subject.length > 200 || text.length > 20000) return sendJson(req, res, 400, { ok: false, error: 'Email content is too large.', requestId });
        subject = subject.replace(/[\r\n]+/g, ' ');
        type = detectType(body, subject, text);
        if (TYPES[type].kind === 'code') code = String(body.code || (text.match(/\b(\d{6})\b/) || [])[1] || '');
      }
      const mail = renderEmail({ type, subject, text, code });
      console.log(JSON.stringify({ event: 'gmail_send_start', requestId, to, subject, type }));
      const result = await sendGmail({ to, subject, text: mail.text, html: mail.html });
      return sendJson(req, res, 200, { ok: true, provider: 'Gmail API', messageId: result.id || null, type, requestId });
    } catch (e) {
      console.error(JSON.stringify({ event: 'gmail_send_error', requestId, error: e.message }));
      return sendJson(req, res, 500, { ok: false, error: e.message || 'Email send failed.', requestId });
    }
  }
  return sendJson(req, res, 404, { ok: false, error: 'Not found.' });
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => console.log(`ESCROW X Email Service v3 listening on 0.0.0.0:${PORT}`));
}
module.exports = { renderEmail, detectType, TYPES };
