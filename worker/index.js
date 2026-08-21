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
          billing: "disabled",
          cloudLifecycle: true
        });
      }

      if (!env.DB) {
        return problem(503, "D1_NOT_CONFIGURED", "The V2 database binding has not been configured.");
      }

      const user = await requireUser(request, ctx, env);

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

      const lifecycleMatch = url.pathname.match(
        /^\/api\/v2\/deals\/([A-Za-z0-9_-]+)\/(reopen|permanent)$/
      );

      if (lifecycleMatch && lifecycleMatch[2] === "reopen" && request.method === "POST") {
        return reopenDeal(env, user, lifecycleMatch[1]);
      }

      if (lifecycleMatch && lifecycleMatch[2] === "permanent" && request.method === "DELETE") {
        return permanentlyDeleteDeal(env, user, lifecycleMatch[1]);
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

      return problem(404, "NOT_FOUND", "The requested V2 endpoint does not exist.");
    } catch (error) {
      console.error("V2 API failure", error);
      return problem(500, "INTERNAL_ERROR", "The request could not be completed.");
    }
  }
};

async function requireUser(request, ctx, env) {
  const identity = await resolveAccessIdentity(request, ctx);
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

async function resolveAccessIdentity(request, ctx) {
  if (ctx.access) {
    const identity = await ctx.access.getIdentity();
    if (identity?.email) return identity;
  }

  const cookie = request.headers.get("cookie") || "";
  const assertion = request.headers.get("cf-access-jwt-assertion") || "";

  if (!cookie && !assertion) return null;

  const headers = new Headers();

  if (cookie) headers.set("cookie", cookie);
  if (assertion) headers.set("cf-access-jwt-assertion", assertion);

  const identityUrl = new URL("/cdn-cgi/access/get-identity", request.url);
  const response = await fetch(identityUrl, {
    method: "GET",
    headers,
    redirect: "manual"
  });

  if (!response.ok) {
    console.warn("Access identity lookup failed", response.status);
    return null;
  }

  const identity = await response.json();
  return identity?.email ? identity : null;
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

function planSummary() {
  return {
    free: { dealLimit: 10, billingEnabled: false },
    professional: { dealLimit: 1000, billingEnabled: false }
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
  const input = await readJson(request);
  const existing = await env.DB.prepare(
    "SELECT id, updated_at FROM deals WHERE id = ? AND owner_id = ?"
  ).bind(id, user.id).first();

  if (!existing) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");

  const expectedUpdatedAt = cleanText(input.expectedUpdatedAt, 80);
  if (expectedUpdatedAt && expectedUpdatedAt !== existing.updated_at) {
    return json({
      error: {
        code: "CLOUD_CONFLICT",
        message: "This cloud deal was changed on another device. Refresh before replacing it.",
        currentUpdatedAt: existing.updated_at
      }
    }, 409);
  }

  const deal = normalizeDeal(input, id);
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

  return json({ deal: { ...deal, id, archived: false, updatedAt: now } });
}

async function archiveDeal(env, user, id) {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "UPDATE deals SET archived = 1, updated_at = ? WHERE id = ? AND owner_id = ?"
  ).bind(now, id, user.id).run();
  if (!result.meta?.changes) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");
  return json({ deal: { id, archived: true, updatedAt: now } });
}

async function reopenDeal(env, user, id) {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "UPDATE deals SET archived = 0, updated_at = ? WHERE id = ? AND owner_id = ?"
  ).bind(now, id, user.id).run();
  if (!result.meta?.changes) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");
  return json({ deal: { id, archived: false, updatedAt: now } });
}

async function permanentlyDeleteDeal(env, user, id) {
  const result = await env.DB.prepare(
    "DELETE FROM deals WHERE id = ? AND owner_id = ? AND archived = 1"
  ).bind(id, user.id).run();
  if (!result.meta?.changes) {
    return problem(409, "ARCHIVE_REQUIRED", "Archive the cloud deal before permanently deleting it.");
  }
  return json({ deleted: true, id });
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
