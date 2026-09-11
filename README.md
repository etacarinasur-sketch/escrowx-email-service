# ESCROW X P2P — Email Service

First real-email test service. It sends ESCROW X verification codes through Resend.

## Deploy on Render
- Build Command: `npm install`
- Start Command: `npm start`
- Environment variable: `RESEND_API_KEY` = your Resend API key
- Optional `FROM_EMAIL`: `onboarding@resend.dev`
- Optional `ALLOWED_ORIGIN`: `*`

Test `GET /health`.

Then `POST /send-verification` with:
`{"to":"recipient@example.com","code":"123456"}`

Do not put the Resend API key in the HTML or GitHub repository. For production, use a domain you control and verify it with the email provider.
