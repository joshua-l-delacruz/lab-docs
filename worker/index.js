const SECURITY_HEADERS = {
  "content-security-policy": [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://psgc.cloud https://nominatim.openstreetmap.org",
    "frame-src 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "upgrade-insecure-requests"
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": [
    "geolocation=(self)",
    "camera=()",
    "microphone=()",
    "payment=()",
    "usb=()",
    "interest-cohort=()"
  ].join(", "),
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none"
};

const HOME_SECURITY_HEADERS = {
  ...SECURITY_HEADERS,
  "content-security-policy": [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self' 'sha256-XLuFGznggQHklfN0GjPo7D/tFTj3zUFGF3GyJh9g2OE='",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-src 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "upgrade-insecure-requests"
  ].join("; ")
};

const API_SECURITY_HEADERS = {
  ...SECURITY_HEADERS,
  "content-security-policy": "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'"
};

const JSON_HEADERS = {
  ...API_SECURITY_HEADERS,
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

export const LIVE_APPLICATION_ORIGINS = Object.freeze({
  "calculator.joshuadelacruz.solutions": "https://scientific-calculator-cpp.onrender.com",
  "malware.joshuadelacruz.solutions": "https://global-malware-trends-cpp.onrender.com",
  "spending.joshuadelacruz.solutions": "https://monthly-spending.vercel.app"
});

const MAX_REQUEST_BYTES = 256 * 1024;
const GITHUB_REPOSITORIES_URL = "https://api.github.com/users/joshua-l-delacruz/repos?per_page=100&sort=updated";
const PLAN_LIMITS = {
  free: { active: 10, total: 50 },
  professional: { active: 1000, total: 5000 }
};

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const liveOrigin = LIVE_APPLICATION_ORIGINS[url.hostname];
    if (liveOrigin) {
      return proxyLiveApplication(request, url, liveOrigin);
    }

    if (url.hostname === "www.joshuadelacruz.solutions") {
      url.hostname = "joshuadelacruz.solutions";
      return redirect(url, 308);
    }

    if (["/services", "/services/", "/services/index.html"].includes(url.pathname)) {
      url.pathname = "/";
      url.hash = "contact";
      return redirect(url, 308);
    }

    if (url.pathname === "/api/engineering-evidence" && request.method === "GET") {
      try {
        return await engineeringEvidenceResponse(request, env);
      } catch {
        return problem(502, "EVIDENCE_UNAVAILABLE", "Live engineering evidence is temporarily unavailable.");
      }
    }

    if (url.pathname === "/api/incident-triage" && request.method === "POST") {
      return incidentTriageResponse(request);
    }

    if (!url.pathname.startsWith("/api/v2/")) {
      const assetResponse = await env.ASSETS.fetch(request);
      const usesStrictStaticPolicy =
        url.pathname === "/" ||
        url.pathname === "/index.html" ||
        url.pathname === "/cpp-calculator" ||
        url.pathname === "/cpp-calculator/" ||
        url.pathname === "/cpp-calculator/index.html";
      const policy = usesStrictStaticPolicy
        ? HOME_SECURITY_HEADERS
        : SECURITY_HEADERS;
      return secureResponse(assetResponse, policy);
    }

    try {
      if (url.pathname === "/api/v2/health" && request.method === "GET") {
        return json({
          ok: true,
          version: "2.1.1",
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
        const isBrowserNavigation =
          request.headers.get("sec-fetch-mode") === "navigate";

        if (isBrowserNavigation) {
          return redirect(
            new URL("/realestate/?brokerSignIn=complete#brokerCloud", url.origin),
            303
          );
        }

        const returnTo = url.searchParams.get("returnTo");

        if (returnTo) {
          const destination = brokerWorkspaceReturn(returnTo, url.origin);

          if (!destination) {
            return problem(400, "INVALID_RETURN_URL", "The sign-in return address is not allowed.");
          }

          return redirect(destination, 303);
        }

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
      if (error instanceof ApiError) {
        return problem(error.status, error.code, error.message);
      }
      console.error("V2 API failure", error);
      return problem(500, "INTERNAL_ERROR", "The request could not be completed.");
    }
  }
};

export async function incidentTriageResponse(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 16384) return problem(413, "PAYLOAD_TOO_LARGE", "Incident payload must be 16 KB or smaller.");
  if (!(request.headers.get("content-type") || "").toLowerCase().includes("application/json")) {
    return problem(415, "JSON_REQUIRED", "Send the incident as application/json.");
  }
  let input;
  try { input = await request.json(); } catch { return problem(400, "INVALID_JSON", "The request body is not valid JSON."); }
  const description = String(input?.description || "").trim();
  if (description.length < 10 || description.length > 4000) return problem(400, "INVALID_DESCRIPTION", "Description must contain 10 to 4,000 characters.");
  const text = `${String(input.short_description || "")} ${description}`;
  const rules = [
    ["Security", "Security Operations", /ransomware|malware|phishing|compromis|data leak/i],
    ["Identity & Access", "Microsoft 365 / Identity", /password|login|mfa|authenticat|credential/i],
    ["Network", "Network Connectivity", /vpn|wifi|network|dns|internet/i],
    ["Endpoint", "Managed Endpoint", /laptop|desktop|device|intune|disk|cpu/i],
    ["Application", "Business Application", /application|website|portal|crash/i]
  ];
  const match = rules.find(([, , pattern]) => pattern.test(text));
  const category = match?.[0] || "General IT";
  const service = match?.[1] || "Service Desk";
  const users = Math.max(1, Math.min(100000, Number(input.affected_users) || 1));
  const security = category === "Security";
  const outage = /all users|site[- ]wide|company[- ]wide|complete outage|service down/i.test(text);
  let priority = "P3";
  if (security || (Boolean(input.business_critical) && outage)) priority = "P1";
  else if (outage || users >= 25 || Boolean(input.business_critical)) priority = "P2";
  const team = security ? "Security Operations" : category === "Identity & Access" ? "IAM Support" : category === "Network" ? "Network Operations" : "Service Desk / Application Owner";
  const actions = security ? ["Preserve available evidence", "Isolate affected assets only when authorized", "Escalate to Security Operations"] : category === "Identity & Access" ? ["Verify identity through the approved process", "Check account and authentication state", "Review recent password, MFA and session changes"] : category === "Network" ? ["Confirm affected scope", "Collect DNS, connection and VPN status", "Compare with monitoring and known outages"] : ["Confirm impact, scope and start time", "Collect exact errors and recent changes", "Check known issues before assignment"];
  return json({ schema_version: "1.0", execution: "cloudflare-worker", category, service, priority, confidence: match ? 0.82 : 0.55, escalation_team: team, human_review_required: priority === "P1" || priority === "P2" || !match, initial_actions: actions, ai_status: "not_configured", data_notice: "Use sanitized data only; human validation required." });
}

export async function engineeringEvidenceResponse(request, env, fetchImpl = fetch, now = new Date()) {
  const response = await fetchImpl(GITHUB_REPOSITORIES_URL, {
    headers: {
      accept: "application/vnd.github+json",
      "user-agent": "joshuadelacruz-solutions-evidence",
      "x-github-api-version": "2022-11-28"
    },
    cf: { cacheEverything: true, cacheTtl: 300 }
  });

  if (!response.ok) throw new Error(`GitHub returned ${response.status}`);
  const repositories = await response.json();
  if (!Array.isArray(repositories)) throw new Error("Invalid GitHub response");

  const projects = repositories.filter(repository => !repository.fork && repository.name !== "joshua-l-delacruz");
  const recentThreshold = now.getTime() - 30 * 24 * 60 * 60 * 1000;
  const languages = new Set(projects.map(repository => repository.language).filter(Boolean));
  const latest = projects.reduce((current, repository) =>
    !current || Date.parse(repository.pushed_at) > Date.parse(current.pushed_at) ? repository : current, null);
  const version = env.CF_VERSION_METADATA || {};
  const evidence = {
    github: {
      repositories: projects.length,
      recentlyUpdated: projects.filter(repository => Date.parse(repository.pushed_at) >= recentThreshold).length,
      languages: languages.size,
      latestRepository: latest?.name || "Unavailable",
      latestPushAt: latest?.pushed_at || null
    },
    cloudflare: {
      deployedAt: version.timestamp || null,
      version: version.id ? String(version.id).slice(0, 8) : "local",
      edge: request.cf?.colo || "Cloudflare"
    },
    refreshedAt: now.toISOString()
  };

  const headers = new Headers(JSON_HEADERS);
  headers.set("cache-control", "public, max-age=300, stale-while-revalidate=600");
  return new Response(JSON.stringify(evidence), { headers });
}

export async function proxyLiveApplication(request, publicUrl, origin, fetchImpl = fetch) {
  const originUrl = new URL(publicUrl.pathname + publicUrl.search, origin);
  const response = await fetchImpl(new Request(originUrl, request));
  const headers = new Headers(response.headers);
  const location = headers.get("location");

  if (location) {
    const destination = new URL(location, originUrl);
    const originHost = new URL(origin).hostname;

    if (destination.hostname === originHost) {
      destination.protocol = publicUrl.protocol;
      destination.hostname = publicUrl.hostname;
      destination.port = "";
      headers.set("location", destination.toString());
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

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

function brokerWorkspaceReturn(value, origin) {
  try {
    const destination = new URL(value, origin);

    if (
      destination.origin !== origin ||
      destination.pathname !== "/realestate/"
    ) {
      return null;
    }

    return destination.pathname + destination.search + destination.hash;
  } catch {
    return null;
  }
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
  const limits = limitsFor(user);
  const counts = await env.DB.prepare(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN archived = 0 THEN 1 ELSE 0 END) AS active
       FROM deals WHERE owner_id = ?`
  ).bind(user.id).first();

  if (Number(counts?.active || 0) >= limits.active) {
    return problem(403, "PLAN_LIMIT_REACHED", "Upgrade the workspace plan to save more active deals.");
  }

  if (Number(counts?.total || 0) >= limits.total) {
    return problem(403, "STORAGE_LIMIT_REACHED", "Permanently delete archived cloud deals before saving another deal.");
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
  const expectedUpdatedAt = cleanText(input.expectedUpdatedAt, 80);
  const deal = normalizeDeal(input, id);
  const now = new Date().toISOString();

  const result = await env.DB.prepare(
    `UPDATE deals SET
       title = ?, status = ?, client_name = ?, client_email = ?,
       property_type = ?, selling_price = ?, location_label = ?,
       payload_json = ?, updated_at = ?
     WHERE id = ? AND owner_id = ? AND archived = 0
       AND (? = '' OR updated_at = ?)`
  ).bind(
    deal.title, deal.status, deal.clientName, deal.clientEmail,
    deal.propertyType, deal.sellingPrice, deal.locationLabel,
    JSON.stringify(deal.payload), now, id, user.id,
    expectedUpdatedAt, expectedUpdatedAt
  ).run();

  if (result.meta?.changes) {
    return json({ deal: { ...deal, id, archived: false, updatedAt: now } });
  }

  const current = await env.DB.prepare(
    "SELECT archived, updated_at FROM deals WHERE id = ? AND owner_id = ?"
  ).bind(id, user.id).first();

  if (!current) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");
  if (current.archived) {
    return problem(409, "DEAL_ARCHIVED", "Reopen the cloud deal before updating it.");
  }

  return json({
    error: {
      code: "CLOUD_CONFLICT",
      message: "This cloud deal was changed on another device. Refresh before replacing it.",
      currentUpdatedAt: current.updated_at
    }
  }, 409);
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
  const limit = limitsFor(user).active;
  const result = await env.DB.prepare(
    `UPDATE deals SET archived = 0, updated_at = ?
      WHERE id = ? AND owner_id = ? AND archived = 1
        AND (SELECT COUNT(*) FROM deals WHERE owner_id = ? AND archived = 0) < ?`
  ).bind(now, id, user.id, user.id, limit).run();

  if (result.meta?.changes) {
    return json({ deal: { id, archived: false, updatedAt: now } });
  }

  const current = await env.DB.prepare(
    "SELECT archived FROM deals WHERE id = ? AND owner_id = ?"
  ).bind(id, user.id).first();

  if (!current) return problem(404, "DEAL_NOT_FOUND", "The deal was not found.");
  if (!current.archived) return problem(409, "DEAL_ALREADY_ACTIVE", "The cloud deal is already active.");
  return problem(403, "PLAN_LIMIT_REACHED", "Archive another active deal before reopening this one.");
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

  if (!title) throw new ApiError(400, "INVALID_DEAL", "A deal title is required.");

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
  if (!type.toLowerCase().includes("application/json")) {
    throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Expected application/json.");
  }

  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The request body exceeds the 256 KB limit.");
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The request body exceeds the 256 KB limit.");
  }

  let value;
  try {
    value = JSON.parse(body);
  } catch {
    throw new ApiError(400, "INVALID_JSON", "The request body is not valid JSON.");
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "INVALID_JSON", "The request body must be a JSON object.");
  }

  return value;
}

function hasSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return origin === new URL(request.url).origin;
}

function isMutation(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(method);
}

function limitsFor(user) {
  return user.plan === "professional" ? PLAN_LIMITS.professional : PLAN_LIMITS.free;
}

function cleanText(value, limit) {
  return String(value || "").trim().slice(0, limit);
}

function secureResponse(response, policy = SECURITY_HEADERS) {
  const headers = new Headers(response.headers);

  if (headers.get("content-type")?.toLowerCase() === "text/html") {
    headers.set("content-type", "text/html; charset=utf-8");
  }

  for (const [name, value] of Object.entries(policy)) {
    headers.set(name, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function redirect(location, status = 303) {
  return secureResponse(
    new Response(null, {
      status,
      headers: {
        location: String(location),
        "cache-control": "no-store"
      }
    })
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function problem(status, code, message) {
  return json({ error: { code, message } }, status);
}

export {
  ApiError,
  MAX_REQUEST_BYTES,
  PLAN_LIMITS,
  API_SECURITY_HEADERS,
  HOME_SECURITY_HEADERS,
  GITHUB_REPOSITORIES_URL,
  SECURITY_HEADERS,
  cleanText,
  hasSameOrigin,
  limitsFor,
  normalizeDeal,
  readJson,
  secureResponse
};
