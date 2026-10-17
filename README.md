# ESCROW X P2P — Email Service v3

Gmail API (OAuth). Start: `npm start`. Health check: `GET /health`.

## Environment variables (Render)
Required: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `FROM_EMAIL`, `PUBLIC_BASE_URL` (this service's public URL, used for the logo).
Strongly recommended:
- `EMAIL_API_KEY` — shared secret. When set, `/send-email` and `/send-verification` require `Authorization: Bearer <key>`. Set the SAME value in the `escrowx-api` service.
- `ALLOWED_ORIGIN` — exact marketplace domain(s), comma separated.
- `APP_URL` — link shown in the email footer.
- `RATE_IP_MAX`, `RATE_RECIPIENT_MAX` — rate limits.
Optional: `ENABLE_PREVIEW=1` enables `/preview` to view each template in the browser (turn it off afterwards).

## Templates
verification, login_code, login_alert, password_recovery, admin_recovery, withdrawal_code, deposit, withdrawal_done, order, support, generic.
Chosen by `type` / `policyKey` or by the subject. All content is in English. The logo is served from `/assets/logo.png` (no attachment).
