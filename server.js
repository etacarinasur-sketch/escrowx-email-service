const http = require("http");

const PORT = Number(process.env.PORT || 10000);
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const RESEND_TIMEOUT_MS = Math.max(10000, Number(process.env.RESEND_TIMEOUT_MS || 60000));

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "600",
    "Vary": "Origin"
  };
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    ...corsHeaders(),
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify(data));
}

function sendNoContent(res) {
  res.writeHead(204, {
    ...corsHeaders(),
    "Cache-Control": "no-store"
  });
  res.end();
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 100000) {
        reject(new Error("Request body too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

async function sendResendEmail({to, subject, html, text, requestId}) {
  if (!RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured.");
  if (!FROM_EMAIL) throw new Error("FROM_EMAIL is not configured.");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RESEND_TIMEOUT_MS);

  try {
    const startedAt = Date.now();

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        from: FROM_EMAIL,
        to: [to],
        subject,
        html,
        text
      }),
      signal: controller.signal
    });

    const data = await r.json().catch(() => ({}));

    console.log(JSON.stringify({
      event: "resend_response",
      requestId,
      status: r.status,
      ok: r.ok,
      elapsedMs: Date.now() - startedAt,
      messageId: data?.id || null,
      error: data?.message || data?.error || null
    }));

    if (!r.ok) {
      throw new Error(
        data?.message ||
        data?.error ||
        `Resend HTTP ${r.status}`
      );
    }

    return data;
  } catch (e) {
    if (e?.name === "AbortError") {
      throw new Error(`Resend request timed out after ${RESEND_TIMEOUT_MS} ms.`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function validEmail(v) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(v || "").trim());
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    return sendNoContent(res);
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "ESCROW X P2P Email Service",
      provider: "Resend",
      configured: Boolean(RESEND_API_KEY),
      from: FROM_EMAIL,
      resendTimeoutMs: RESEND_TIMEOUT_MS
    });
  }

  if (
    req.method === "POST" &&
    (req.url === "/send-verification" || req.url === "/send-email")
  ) {
    const requestId =
      `email_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    try {
      const body = await readBody(req);
      const to = String(body.to || "").trim();

      if (!validEmail(to)) {
        return sendJson(res, 400, {
          ok: false,
          error: "Invalid recipient email.",
          requestId
        });
      }

      let subject;
      let text;
      let html;

      if (req.url === "/send-verification") {
        const code = String(body.code || "").trim();

        if (!/^\d{6}$/.test(code)) {
          return sendJson(res, 400, {
            ok: false,
            error: "Verification code must be 6 digits.",
            requestId
          });
        }

        subject = String(
          body.subject || "ESCROW X — Verify your email"
        ).trim();

        text =
          `ESCROW X P2P MARKETPLACE\n\n` +
          `Welcome to EscrowX.\n\n` +
          `To complete your registration, enter the verification code below in the EscrowX Marketplace.\n\n` +
          `Verification code: ${code}\n\n` +
          `This code expires in 10 minutes and is valid only for this verification request.\n\n` +
          `SECURITY NOTICE\n` +
          `Never share this verification code with anyone. If you did not create an EscrowX account, you can safely ignore this email.\n\n` +
          `This is an automated security message from EscrowX P2P Marketplace.`;

        html =
          `<!doctype html>` +
          `<html><body style="margin:0;padding:0;background:#f4f7fb;font-family:Arial,Helvetica,sans-serif;color:#24324a">` +
          `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7fb;padding:28px 12px">` +
          `<tr><td align="center">` +
          `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:620px;background:#ffffff;border:1px solid #dfe7f1;border-radius:18px;overflow:hidden">` +
          `<tr><td style="padding:28px 32px;background:#0b1730;text-align:center">` +
          `<div style="font-size:30px;line-height:1;font-weight:900;color:#ffffff;letter-spacing:1px">ESCROW<span style="color:#18a0ff">X</span></div>` +
          `<div style="margin-top:8px;font-size:12px;letter-spacing:3px;color:#aebbd0">P2P MARKETPLACE</div>` +
          `</td></tr>` +
          `<tr><td style="padding:38px 36px 30px">` +
          `<div style="font-size:30px;line-height:1.2;font-weight:800;color:#173a78;text-align:center">Verify your email</div>` +
          `<div style="margin-top:14px;font-size:15px;line-height:1.65;color:#596b84;text-align:center">Thank you for creating your EscrowX account. To complete your registration, enter the verification code below.</div>` +
          `<div style="margin:26px 0;padding:20px 16px;text-align:center;background:#f2f7ff;border:1px solid #cfe1fa;border-radius:14px">` +
          `<div style="font-size:11px;font-weight:800;letter-spacing:1.4px;color:#71829a;text-transform:uppercase">Email verification code</div>` +
          `<div style="margin-top:10px;font-size:38px;line-height:1.15;font-weight:900;letter-spacing:10px;color:#1456c8">${code}</div>` +
          `<div style="margin-top:10px;font-size:13px;color:#66758b">Expires in <strong style="color:#173a78">10 minutes</strong></div>` +
          `</div>` +
          `<div style="font-size:14px;line-height:1.65;color:#596b84">Enter this code in the <strong style="color:#24324a">EscrowX Marketplace</strong> verification window. The code is single-use for this verification request.</div>` +
          `<div style="margin-top:22px;padding:15px 17px;border-left:4px solid #18a0ff;background:#f7fbff;color:#596b84;font-size:13px;line-height:1.6">` +
          `<strong style="color:#173a78">Security notice</strong><br>` +
          `Never share your verification code with anyone. If you did not create an EscrowX account, you can safely ignore this email.` +
          `</div>` +
          `</td></tr>` +
          `<tr><td style="padding:18px 28px;background:#f8fafc;border-top:1px solid #e4eaf2;text-align:center">` +
          `<div style="font-size:12px;color:#718096">EscrowX P2P Marketplace · Secure peer-to-peer exchange</div>` +
          `<div style="font-size:11px;color:#94a1b2;margin-top:6px">This is an automated security message. Please do not reply.</div>` +
          `</td></tr>` +
          `</table>` +
          `</td></tr></table>` +
          `</body></html>`;
      } else {
        subject = String(
          body.subject || "ESCROW X P2P notification"
        ).trim();

        text = String(body.text || "").trim();
        html = String(body.html || "").trim();

        if (!subject || !text) {
          return sendJson(res, 400, {
            ok: false,
            error: "Subject and text are required.",
            requestId
          });
        }

        if (!html) {
          const escaped = text.replace(
            /[&<>]/g,
            c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])
          );
          html =
            `<pre style="font-family:Arial,sans-serif;white-space:pre-wrap">` +
            escaped +
            `</pre>`;
        }

        if (
          subject.length > 200 ||
          text.length > 20000 ||
          html.length > 50000
        ) {
          return sendJson(res, 400, {
            ok: false,
            error: "Email content is too large.",
            requestId
          });
        }
      }

      console.log(JSON.stringify({
        event: "email_send_start",
        requestId,
        to,
        subject
      }));

      const result = await sendResendEmail({
        to,
        subject,
        html,
        text,
        requestId
      });

      return sendJson(res, 200, {
        ok: true,
        provider: "Resend",
        messageId: result.id || null,
        requestId
      });
    } catch (e) {
      console.error(JSON.stringify({
        event: "email_send_error",
        requestId,
        error: e?.message || "Email send failed."
      }));

      return sendJson(res, 500, {
        ok: false,
        error: e?.message || "Email send failed.",
        requestId
      });
    }
  }

  return sendJson(res, 404, {
    ok: false,
    error: "Not found."
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `ESCROW X Email Service listening on 0.0.0.0:${PORT}`
  );
});
