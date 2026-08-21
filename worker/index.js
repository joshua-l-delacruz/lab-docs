const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/v2/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      if (url.pathname === "/api/v2/health" && request.method === "GET") {
        return json({
          ok: true,
          version: "2.0-foundation",
          database: Boolean(env.DB),
          stripe: Boolean(env.STRIPE_SECRET_KEY && env.STRIPE_PRICE_PRO)
        });
      }

      if (url.pathname === "/api/v2/stripe/webhook" && request.method === "POST") {
        return handleStripeWebhook(request, env);
      }

      if (!env.DB) {
        return problem(503, "D1_NOT_CONFIGURED", "The V2 database binding has not been configured.");
      }

      const user = await requireUser(ctx, env);

      if (!user) {
        return problem(401, "AUTHENTICATION_REQUIRED", "Sign in through Cloudflare Access to use the broker workspace.");
      }

      if (isMutation(request.method) && !hasSameOrigin(request)) {
        return problem(403, "INVALID_ORIGIN", "The request origin is not allowed.");
      }

      if (url.pathname === "/api/v2/me" && request.method === "GET") {
        return json({ user: publicUser(user), plans: planSummary(env) });
      }

      if (url.pathname === "/api/v2/deals" && request.method === "GET") {
        return listDeals(env, user, url);
      }

      if (url.pathname === "/api/v2/deals" && request.method === "POST") {
        return createDeal(request, env, user);
      }

      const dealMatch = url.pathname.match(/^\/api\/v2\/deals\/([A-Za-z0-9_-]+)$/);

      if (dealMatch && request.method === "GET") {
        return getDeal(env, user, dealMatch[1]);
      }

      if (dealMatch && request.method === "PUT") {
        return updateDeal(request, env, user, dealMatch[1]);
      }

      if (dealMatch && request.method === "DELETE") {
        return archiveDeal(env, user, dealMatch[1]);
      }

      if (url.pathname === "/api/v2/billing/checkout" && request.method === "POST") {
        return createCheckout(env, user, url.origin);
      }

      if (url.pathname === "/api/v2/billing/portal" && request.method === "POST") {
        return createPortal(env, user, url.origin);
      }

      return problem(404, "NOT_FOUND", "The requested V2 endpoint does not exist.");
    } catch (error) {
      console.error("V2 API failure", error);
      return problem(500, "INTERNAL_ERROR", "The request could not be completed.");
    }
  }
};

async function requireUser(ctx, env) {
  if (!ctx.access) return null;

  const identity = await ctx.access.getIdentity();
  const email = String(identity?.email || "").trim().toLowerCase();

  if (!email) return null;

  const id = String(identity?.id || identity?.sub || email);
  const name = String(identity?.name || email.split("@")[0]);
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO users (id, email, name, plan, subscription_status, created_at, updated_at)
     VALUES (?, ?, ?, 'free', 'inactive', ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       email = excluded.email,
       name = excluded.name,
       updated_at = excluded.updated_at`
  ).bind(id, email, name, now, now).run();

  return env.DB.prepare(
    `SELECT id, email, name, plan, subscription_status, stripe_customer_id,
            stripe_subscription_id, created_at, updated_at
       FROM users WHERE id = ?`
  ).bind(id).first();
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan,
    subscriptionStatus: user.subscription_status,
    createdAt: user.created_at,
    updatedAt: user.updated_at
  };
}

function planSummary(env) {
  return {
    free: { dealLimit: 10, billingEnabled: false },
    professional: {
      dealLimit: 1000,
      billingEnabled: Boolean(env.STRIPE_SECRET_KEY && env.STRIPE_PRICE_PRO)
    }
  };
}

async function listDeals(env, user, url) {
  const includeArchived = url.searchParams.get("archived") === "true";
  const rows = await env.DB.prepare(
    `SELECT id, title, status, client_name, client_email, property_type,
            selling_price, location_label, archived, created_at, updated_at
       FROM deals
      WHERE owner_id = ? AND (? = 1 OR archived = 0)
      ORDER BY updated_at DESC
      LIMIT 200`
  ).bind(user.id, includeArchived ? 1 : 0).all();

  return json({ deals: rows.results || [] });
}

async function getDeal(env, user, id) {
  const row = await env.DB.prepare(
    "SELECT * FROM deals WHERE id = ? AND owner_id = ?"
  ).bind(id, user.id).first();

  if (!row) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");

  return json({ deal: deserializeDeal(row) });
}

async function createDeal(request, env, user) {
  const input = await readJson(request);
  const limit = user.plan === "professional" ? 1000 : 10;
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM deals WHERE owner_id = ? AND archived = 0"
  ).bind(user.id).first();

  if (Number(count?.total || 0) >= limit) {
    return problem(403, "PLAN_LIMIT_REACHED", "Upgrade the workspace plan to save more active deals.");
  }

  const id = crypto.randomUUID();
  const deal = normalizeDeal(input, id);
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO deals (
       id, owner_id, title, status, client_name, client_email, property_type,
       selling_price, location_label, payload_json, archived, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
  ).bind(
    id, user.id, deal.title, deal.status, deal.clientName, deal.clientEmail,
    deal.propertyType, deal.sellingPrice, deal.locationLabel,
    JSON.stringify(deal.payload), now, now
  ).run();

  return json({ deal: { ...deal, id, archived: false, createdAt: now, updatedAt: now } }, 201);
}

async function updateDeal(request, env, user, id) {
  const existing = await env.DB.prepare(
    "SELECT id FROM deals WHERE id = ? AND owner_id = ?"
  ).bind(id, user.id).first();

  if (!existing) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");

  const deal = normalizeDeal(await readJson(request), id);
  const now = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE deals SET
       title = ?, status = ?, client_name = ?, client_email = ?,
       property_type = ?, selling_price = ?, location_label = ?,
       payload_json = ?, updated_at = ?
     WHERE id = ? AND owner_id = ?`
  ).bind(
    deal.title, deal.status, deal.clientName, deal.clientEmail,
    deal.propertyType, deal.sellingPrice, deal.locationLabel,
    JSON.stringify(deal.payload), now, id, user.id
  ).run();

  return json({ deal: { ...deal, id, updatedAt: now } });
}

async function archiveDeal(env, user, id) {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "UPDATE deals SET archived = 1, updated_at = ? WHERE id = ? AND owner_id = ?"
  ).bind(now, id, user.id).run();

  if (!result.meta?.changes) {
    return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");
  }

  return new Response(null, { status: 204 });
}

function normalizeDeal(input, id) {
  const payload = input && typeof input === "object" ? input : {};
  const title = cleanText(payload.title || payload.dealName, 160);

  if (!title) throw new Error("A deal title is required.");

  return {
    id,
    title,
    status: cleanText(payload.status || "Active", 40),
    clientName: cleanText(payload.clientName, 160),
    clientEmail: cleanText(payload.clientEmail, 320).toLowerCase(),
    propertyType: cleanText(payload.propertyType, 80),
    sellingPrice: Math.max(0, Number(payload.sellingPrice) || 0),
    locationLabel: cleanText(payload.locationLabel, 240),
    payload
  };
}

function deserializeDeal(row) {
  let payload = {};
  try { payload = JSON.parse(row.payload_json || "{}"); } catch {}
  return {
    ...payload,
    id: row.id,
    title: row.title,
    status: row.status,
    clientName: row.client_name,
    clientEmail: row.client_email,
    propertyType: row.property_type,
    sellingPrice: row.selling_price,
    locationLabel: row.location_label,
    archived: Boolean(row.archived),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function createCheckout(env, user, origin) {
  requireStripe(env);

  if (user.subscription_status === "active" && user.stripe_customer_id) {
    return createPortal(env, user, origin);
  }

  const form = new URLSearchParams({
    mode: "subscription",
    "line_items[0][price]": env.STRIPE_PRICE_PRO,
    "line_items[0][quantity]": "1",
    customer_email: user.email,
    client_reference_id: user.id,
    "metadata[user_id]": user.id,
    "subscription_data[metadata][user_id]": user.id,
    success_url: `${origin}/realestate/?billing=success`,
    cancel_url: `${origin}/realestate/?billing=cancelled`
  });

  const session = await stripeRequest(env, "/v1/checkout/sessions", form);
  return json({ url: session.url });
}

async function createPortal(env, user, origin) {
  requireStripe(env);

  if (!user.stripe_customer_id) {
    return problem(409, "NO_STRIPE_CUSTOMER", "No billing customer exists for this account.");
  }

  const form = new URLSearchParams({
    customer: user.stripe_customer_id,
    return_url: `${origin}/realestate/`
  });

  const session = await stripeRequest(env, "/v1/billing_portal/sessions", form);
  return json({ url: session.url });
}

async function stripeRequest(env, path, form) {
  const response = await fetch("https://api.stripe.com" + path, {
    method: "POST",
    headers: {
      authorization: "Bearer " + env.STRIPE_SECRET_KEY,
      "content-type": "application/x-www-form-urlencoded"
    },
    body: form
  });

  const data = await response.json();

  if (!response.ok) {
    console.error("Stripe API error", data);
    throw new Error("Stripe rejected the billing request.");
  }

  return data;
}

async function handleStripeWebhook(request, env) {
  if (!env.DB || !env.STRIPE_WEBHOOK_SECRET) {
    return problem(503, "BILLING_NOT_CONFIGURED", "Stripe webhook configuration is incomplete.");
  }

  const body = await request.text();
  const signature = request.headers.get("stripe-signature") || "";

  if (!(await verifyStripeSignature(body, signature, env.STRIPE_WEBHOOK_SECRET))) {
    return problem(400, "INVALID_SIGNATURE", "The Stripe webhook signature is invalid.");
  }

  const event = JSON.parse(body);
  const inserted = await env.DB.prepare(
    "INSERT OR IGNORE INTO webhook_events (id, event_type, received_at) VALUES (?, ?, ?)"
  ).bind(event.id, event.type, new Date().toISOString()).run();

  if (!inserted.meta?.changes) return json({ received: true, duplicate: true });

  const object = event.data?.object || {};
  const userId = object.metadata?.user_id || object.client_reference_id;

  if (event.type === "checkout.session.completed" && userId) {
    await env.DB.prepare(
      `UPDATE users SET stripe_customer_id = ?, stripe_subscription_id = ?,
       plan = 'professional', subscription_status = 'active', updated_at = ?
       WHERE id = ?`
    ).bind(object.customer, object.subscription, new Date().toISOString(), userId).run();
  }

  if (event.type.startsWith("customer.subscription.")) {
    const status = String(object.status || "inactive");
    const plan = ["active", "trialing"].includes(status) ? "professional" : "free";
    await env.DB.prepare(
      `UPDATE users SET plan = ?, subscription_status = ?,
       stripe_subscription_id = ?, updated_at = ?
       WHERE stripe_customer_id = ?`
    ).bind(plan, status, object.id, new Date().toISOString(), object.customer).run();
  }

  return json({ received: true });
}

async function verifyStripeSignature(payload, header, secret) {
  const parts = Object.fromEntries(
    header.split(",").map(part => {
      const index = part.indexOf("=");
      return [part.slice(0, index), part.slice(index + 1)];
    })
  );

  const timestamp = Number(parts.t);
  const expected = parts.v1;

  if (!timestamp || !expected || Math.abs(Date.now() / 1000 - timestamp) > 300) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(timestamp + "." + payload)
  );

  const actual = Array.from(new Uint8Array(signature))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  return constantTimeEqual(actual, expected);
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) {
    result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return result === 0;
}

function requireStripe(env) {
  if (!env.STRIPE_SECRET_KEY || !env.STRIPE_PRICE_PRO) {
    throw new Error("Stripe billing has not been configured.");
  }
}

async function readJson(request) {
  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("Expected application/json.");
  return request.json();
}

function hasSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return origin === new URL(request.url).origin;
}

function isMutation(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(method);
}

function cleanText(value, limit) {
  return String(value || "").trim().slice(0, limit);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function problem(status, code, message) {
  return json({ error: { code, message } }, status);
}
