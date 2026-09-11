const http = require("http");

const PORT = Number(process.env.PORT || 10000);
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 100000) req.destroy();
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

async function sendResendEmail({to, subject, html, text}) {
  if (!RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured.");

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html, text })
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data?.message || data?.error || `Resend HTTP ${r.status}`);
  return data;
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") return sendJson(res, 204, {ok:true});

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "ESCROW X P2P Email Service",
      provider: "Resend",
      configured: Boolean(RESEND_API_KEY),
      from: FROM_EMAIL
    });
  }

  if (req.method === "POST" && req.url === "/send-verification") {
    try {
      const body = await readBody(req);
      const to = String(body.to || "").trim();
      const code = String(body.code || "").trim();

      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to))
        return sendJson(res, 400, {ok:false, error:"Invalid recipient email."});
      if (!/^\d{6}$/.test(code))
        return sendJson(res, 400, {ok:false, error:"Verification code must be 6 digits."});

      const result = await sendResendEmail({
        to,
        subject: "ESCROW X — Verify your email",
        text: `ESCROW X P2P\n\nYour email verification code is: ${code}\n\nThis code expires in 10 minutes.\n\nIf you did not create an ESCROW X account, you can ignore this email.`,
        html: `<!doctype html><html><body style="font-family:Arial,sans-serif;line-height:1.5"><h2>ESCROW X P2P</h2><p>Your email verification code is:</p><p style="font-size:30px;font-weight:700;letter-spacing:6px">${code}</p><p>This code expires in <strong>10 minutes</strong>.</p><p>If you did not create an ESCROW X account, you can ignore this email.</p></body></html>`
      });

      return sendJson(res, 200, {ok:true, provider:"Resend", messageId:result.id || null});
    } catch (e) {
      return sendJson(res, 500, {ok:false, error:e.message || "Email send failed."});
    }
  }

  return sendJson(res, 404, {ok:false, error:"Not found."});
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ESCROW X Email Service listening on 0.0.0.0:${PORT}`);
});
