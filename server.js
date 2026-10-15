const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 10000);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'escrowx.verifier@gmail.com';
const BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://escrowx-email-service.onrender.com').replace(/\/$/, '');
const REDIRECT_URI = `${BASE_URL}/oauth/callback`;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const oauthStates = new Map();

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST,GET,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin'
  };
}
function sendJson(res, status, data) {
  res.writeHead(status, { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(html);
}
function sendNoContent(res) {
  res.writeHead(204, { ...corsHeaders(), 'Cache-Control': 'no-store' });
  res.end();
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
function validEmail(v) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(v || '').trim()); }
function b64url(value) { return Buffer.from(value).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function htmlEscape(value) { return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }

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

function buildVerificationEmail(code) {
  const text = `ESCROWX MARKETPLACE\n\nTu código para verificar tu cuenta es: ${code}\n\nVence en 15 minutos.\nSi no lo solicitaste, ignora este correo.\n\nNunca compartas este código con nadie.`;
  const html = `<!doctype html><html lang="es"><head><meta charset="utf-8"></head><body style="margin:0;padding:24px 10px;background:#070b16;font-family:Arial,Helvetica,sans-serif;color:#f7faff"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;background:#071126;border:1px solid #075dff;border-radius:22px;overflow:hidden"><tr><td align="center" style="padding:34px 24px 18px;background:radial-gradient(circle at 50% 10%,#103b9a 0,#071126 62%)"><div style="font-size:42px;line-height:1;font-weight:900;letter-spacing:3px;color:#fff">ESCROW<span style="color:#00c9ff">X</span></div><div style="margin-top:10px;font-size:11px;letter-spacing:5px;color:#b9c8e7">MARKETPLACE</div></td></tr><tr><td align="center" style="padding:22px 26px 10px"><div style="font-size:25px;line-height:1.35;font-weight:700;color:#f4f8ff">Tu código para verificar tu cuenta es:</div><div style="margin:24px 0 18px;padding:20px 10px;border:2px solid #008cff;border-radius:16px;background:#061b3c;color:#fff;font-size:42px;font-weight:800;letter-spacing:10px;box-shadow:0 0 18px rgba(0,140,255,.3)">${code}</div><div style="font-size:16px;color:#dce8ff">Vence en <strong>15 minutos</strong>.</div><div style="margin-top:14px;font-size:14px;line-height:1.6;color:#9eacc8">Si no lo solicitaste, ignora este correo.</div></td></tr><tr><td style="padding:26px 22px 28px"><div style="border-top:1px solid #18366b;padding-top:20px;text-align:center;font-size:12px;letter-spacing:2px;color:#5ec7ff">SEGURO&nbsp;&nbsp; · &nbsp;&nbsp;CONFIABLE&nbsp;&nbsp; · &nbsp;&nbsp;RÁPIDO</div><div style="margin-top:18px;text-align:center;font-size:12px;line-height:1.6;color:#8292b2">Nunca compartas este código con nadie. Mensaje automático de seguridad de EscrowX.</div></td></tr></table></td></tr></table></body></html>`;
  return { text, html };
}

async function sendGmail({ to, subject, text, html }) {
  const accessToken = await getAccessToken();
  const boundary = `escrowx_${crypto.randomBytes(12).toString('hex')}`;
  const encodedSubject = `=?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`;
  const mime = [
    `From: EscrowX <${FROM_EMAIL}>`, `To: ${to}`, `Subject: ${encodedSubject}`, 'MIME-Version: 1.0',
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

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  if (req.method === 'OPTIONS') return sendNoContent(res);

  if (req.method === 'GET' && url.pathname === '/health') {
    const configured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REFRESH_TOKEN);
    return sendJson(res, 200, { ok: true, service: 'ESCROW X P2P Email Service', provider: 'Gmail API', configured, from: FROM_EMAIL, oauthRedirectUri: REDIRECT_URI });
  }

  if (req.method === 'GET' && url.pathname === '/oauth/start') {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return sendJson(res, 503, { ok: false, error: 'Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render before starting OAuth.' });
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
    if (url.searchParams.get('error')) return sendHtml(res, 400, '<h2>Autorización cancelada</h2><p>Volvé a iniciar el proceso desde /oauth/start.</p>');
    if (!state || !oauthStates.has(state) || oauthStates.get(state) < Date.now()) return sendHtml(res, 400, '<h2>Solicitud vencida o inválida</h2><p>Volvé a iniciar el proceso desde /oauth/start.</p>');
    oauthStates.delete(state);
    if (!code) return sendHtml(res, 400, '<h2>Falta el código de autorización</h2>');
    try {
      const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code' }) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error_description || data.error || `HTTP ${response.status}`);
      if (!data.refresh_token) throw new Error('Google did not return a refresh token. Revoke this app access from your Google Account and restart OAuth with consent.');
      const safeToken = htmlEscape(data.refresh_token);
      return sendHtml(res, 200, `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>EscrowX OAuth</title><body style="font-family:Arial;background:#081225;color:#fff;padding:24px;max-width:760px;margin:auto"><h2>Autorización de Gmail completada</h2><p>Copiá este token de actualización y guardalo directamente como variable <b>GOOGLE_REFRESH_TOKEN</b> en Render. No lo compartas por chat ni lo publiques.</p><textarea readonly style="width:100%;height:130px;word-break:break-all">${safeToken}</textarea><p>Después de guardarlo en Render, eliminá esta página del historial y no vuelvas a mostrar el token.</p><p>Por seguridad, esta página no almacena el token en el servidor.</p></body></html>`);
    } catch (e) {
      console.error(JSON.stringify({ event: 'oauth_callback_error', error: e.message }));
      return sendHtml(res, 400, `<h2>No se pudo completar OAuth</h2><p>${htmlEscape(e.message)}</p>`);
    }
  }

  if (req.method === 'POST' && (url.pathname === '/send-verification' || url.pathname === '/send-email')) {
    const requestId = `email_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    try {
      const body = await readBody(req);
      const to = String(body.to || '').trim();
      if (!validEmail(to)) return sendJson(res, 400, { ok: false, error: 'Invalid recipient email.', requestId });
      let subject, text, html;
      if (url.pathname === '/send-verification') {
        const code = String(body.code || '').trim();
        if (!/^\d{6}$/.test(code)) return sendJson(res, 400, { ok: false, error: 'Verification code must be 6 digits.', requestId });
        subject = String(body.subject || 'EscrowX — Código de verificación').trim();
        ({ text, html } = buildVerificationEmail(code));
      } else {
        subject = String(body.subject || 'EscrowX Marketplace notification').trim();
        text = String(body.text || '').trim(); html = String(body.html || '').trim();
        if (!subject || !text) return sendJson(res, 400, { ok: false, error: 'Subject and text are required.', requestId });
        if (!html) html = `<pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${htmlEscape(text)}</pre>`;
        if (subject.length > 200 || text.length > 20000 || html.length > 50000) return sendJson(res, 400, { ok: false, error: 'Email content is too large.', requestId });
      }
      console.log(JSON.stringify({ event: 'gmail_send_start', requestId, to, subject }));
      const result = await sendGmail({ to, subject, text, html });
      return sendJson(res, 200, { ok: true, provider: 'Gmail API', messageId: result.id || null, requestId });
    } catch (e) {
      console.error(JSON.stringify({ event: 'gmail_send_error', requestId, error: e.message }));
      return sendJson(res, 500, { ok: false, error: e.message || 'Email send failed.', requestId });
    }
  }
  return sendJson(res, 404, { ok: false, error: 'Not found.' });
});

server.listen(PORT, '0.0.0.0', () => console.log(`ESCROW X Gmail Email Service listening on 0.0.0.0:${PORT}`));
