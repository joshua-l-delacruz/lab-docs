# Real Estate Broker Cloud V2.1.1

## Release status

V2.1.1 is the stable portfolio release of the Philippine Property Transaction Workspace with Broker Cloud synchronization.

Billing remains intentionally disabled. The release does not require Stripe, Xendit, a registered business, or paid subscriptions.

## Included capabilities

- Cloudflare Access authentication for authorized broker accounts
- Owner-scoped D1 deal storage
- Manual local-to-cloud synchronization
- Cross-browser restoration of cloud deals
- Create, update, archive, reopen, and permanent-delete lifecycle
- Optimistic concurrency checks that prevent silent cross-device overwrites
- Free-plan storage limits enforced by the Worker
- Local browser records retained as an offline fallback
- Validated client email and Philippine mobile numbers
- Professional one-page A4 PDF reports at the browser's default 100% scale
- Protected `main` branch with required backend regression tests
- Cloudflare Workers deployment with D1 and static assets

## Production verification

1. Open `https://joshuadelacruz.solutions/realestate/`.
2. Sign in through Cloudflare Access and refresh Broker Cloud.
3. Save a transaction locally, then synchronize it.
4. Update the same deal and confirm it updates rather than duplicates.
5. Load the deal in another authorized browser.
6. Archive, reopen, and permanently delete a test cloud deal.
7. Generate the professional report using A4, default margins, 100% scale, and disabled browser headers and footers.
8. Confirm `/api/v2/health` reports version `2.1.1`, database enabled, billing disabled, and cloud lifecycle enabled.

## Architecture

```text
Browser workspace
  |-- local saved transactions
  |-- Cloudflare Access session
  |
  +--> /api/v2/* Cloudflare Worker
          |-- verified account identity
          |-- owner-scoped authorization
          |-- validation and conflict checks
          |
          +--> D1 SQLite database
```

## Billing position

Subscription endpoints remain disabled until there is a registered business and an appropriate supported payment provider. No payment secrets or live billing configuration are required for this release.
