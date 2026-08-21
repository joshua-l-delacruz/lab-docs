# Real Estate V2.1 Broker Cloud setup

V2.1 provides authenticated broker accounts and cross-device cloud deal management. Payments are deliberately disabled. The existing local workspace and professional PDF report remain available as an offline fallback.

## Architecture

- Cloudflare Worker: same-origin API under `/api/v2/*`
- Cloudflare Access: verified broker identity
- Cloudflare D1: owner-scoped account and deal records
- Browser local storage: offline fallback and unsynchronized work
- Static assets: portfolio, property workspace and reports

## Configured resources

- D1 binding: `DB`
- Database: `realestate-saas`
- Protected Access paths:
  - `/api/v2/me`
  - `/api/v2/deals`
  - `/api/v2/deals/*`
- Public health endpoint: `/api/v2/health`

The Access policy must allow only intended broker accounts. No browser-supplied email header is trusted as identity.

## Cloud deal lifecycle

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v2/me` | Current authenticated account and plan limits |
| `GET` | `/api/v2/deals?archived=true` | Active and archived cloud deals |
| `POST` | `/api/v2/deals` | Upload a saved local deal |
| `GET` | `/api/v2/deals/:id` | Download a complete deal |
| `PUT` | `/api/v2/deals/:id` | Update when the expected cloud timestamp still matches |
| `DELETE` | `/api/v2/deals/:id` | Archive a cloud deal |
| `POST` | `/api/v2/deals/:id/reopen` | Reopen an archived cloud deal |
| `DELETE` | `/api/v2/deals/:id/permanent` | Permanently delete an already archived deal |

Permanent deletion is deliberately two-step: archive first, then type `DELETE` in the browser confirmation.

## Conflict protection

Each local cloud-linked record stores its last successful cloud synchronization timestamp. Updates send that value as `expectedUpdatedAt`.

If another device changed the cloud record, the Worker returns `409 CLOUD_CONFLICT`. The browser refreshes its list and asks the user to load the newer cloud copy instead of silently overwriting it.

## Cross-browser verification

1. Sign in and refresh Broker Cloud in Brave.
2. Save and synchronize a local deal.
3. Sign in and load that deal in Chrome.
4. Change and save it in Chrome, then synchronize it.
5. Change the older Brave copy and attempt to synchronize.
6. Confirm Brave reports **Cloud conflict detected**.
7. Load the cloud copy in Brave and confirm the Chrome changes appear.
8. Archive the cloud deal and confirm it remains recoverable.
9. Reopen it and confirm it returns to the active count.
10. Archive it again, permanently delete it, and confirm the local fallback remains.

## Security and data-safety defaults

- Every query is scoped to the authenticated owner ID.
- Mutations require a same-origin browser request.
- No deal uploads automatically.
- Unsaved forms cannot synchronize.
- Loading cloud data warns before replacing unsynchronized local changes.
- Permanent cloud deletion requires an archived record and typed confirmation.
- Existing D1 tables and records are preserved.
- Backend sources and configuration remain excluded from public static assets.

## Billing status

Billing is disabled. Stripe runtime routes and secrets are not used in V2.1. Existing legacy billing columns remain in D1 to avoid a destructive production migration; they may be repurposed only after a legally eligible payment arrangement is selected and separately verified.
