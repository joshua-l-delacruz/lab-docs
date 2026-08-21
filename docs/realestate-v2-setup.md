# Real Estate V2.0 SaaS setup

This branch adds the server-side foundation for authenticated broker accounts, cloud deals and Stripe subscriptions. The existing V1.5 public workspace remains available while V2 is configured.

## Architecture

- Cloudflare Worker: same-origin API under `/api/v2/*`
- Cloudflare Access: verified broker identity exposed as `ctx.access`
- Cloudflare D1: account, deal and subscription records
- Stripe Checkout: Professional plan subscription
- Stripe Customer Portal: self-service billing
- Stripe webhooks: authoritative subscription status
- Static assets: the existing portfolio and property workspace

## 1. Create and bind D1

From a trusted local checkout:

```powershell
npx wrangler d1 create realestate-saas
npx wrangler d1 migrations apply realestate-saas --remote
```

In Cloudflare, open **Workers & Pages → lab-docs → Bindings → Add binding → D1 database**.

- Variable name: `DB`
- Database: `realestate-saas`

Do not place a database ID in browser JavaScript.

## 2. Configure secure accounts

Open **Workers & Pages → lab-docs → Access** and enable Cloudflare Access for the protected V2 account endpoints.

Require authentication for:

- `/api/v2/me*`
- `/api/v2/deals*`
- `/api/v2/billing/*`

Allow the intended broker email addresses or verified email domain. Keep these endpoints public:

- `/api/v2/health`
- `/api/v2/stripe/webhook`

The Worker rejects account requests when `ctx.access` is absent, so a copied email header cannot impersonate a user.

## 3. Create Stripe products in test mode

In Stripe test mode, create one recurring **Professional** price. Copy its `price_...` identifier.

Add Worker secrets:

```powershell
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
```

Add the non-secret Worker variable `STRIPE_PRICE_PRO` with the recurring Stripe Price ID.

Never commit Stripe secret keys or webhook secrets.

## 4. Register the Stripe webhook

Create this Stripe webhook endpoint:

```text
https://joshuadelacruz.solutions/api/v2/stripe/webhook
```

Subscribe to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

Copy the endpoint signing secret into `STRIPE_WEBHOOK_SECRET`.

## 5. Verify before enabling paid access

1. Request `/api/v2/health`; confirm `database: true` and `stripe: true`.
2. Sign in through Access and request `/api/v2/me`.
3. Create, update, list and archive a test deal.
4. Use a Stripe test card through Checkout.
5. Confirm the webhook changes the account to `professional`.
6. Cancel from the Customer Portal and confirm the account returns to `free`.
7. Review D1 records and Worker logs without exposing personal data.

## Security defaults

- Every deal query is scoped by the authenticated owner ID.
- Mutations require a same-origin browser request.
- Stripe webhook signatures use HMAC SHA-256 and a five-minute tolerance.
- Webhook IDs are stored to prevent duplicate processing.
- Billing status is updated only by verified Stripe events.
- Free accounts are limited to 10 active deals; Professional accounts to 1,000.
- Backend source, migrations and configuration are excluded from public static assets.

## Not enabled by this PR

This foundation does not activate charges, create Stripe products, configure Access policies, create D1 resources or add production secrets. Those are deliberate account-owner actions.
