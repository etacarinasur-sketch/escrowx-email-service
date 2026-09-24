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
          `ESCROW X P2P\n\n` +
          `Your email verification code is: ${code}\n\n` +
          `This code expires in 10 minutes.\n\n` +
          `If you did not create an ESCROW X account, you can ignore this email.`;

        html =
          `<!doctype html><html><body style="font-family:Arial,sans-serif;line-height:1.5">` +
          `<h2>ESCROW X P2P</h2>` +
          `<p>Your email verification code is:</p>` +
          `<p style="font-size:30px;font-weight:700;letter-spacing:6px">${code}</p>` +
          `<p>This code expires in <strong>10 minutes</strong>.</p>` +
          `<p>If you did not create an ESCROW X account, you can ignore this email.</p>` +
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
