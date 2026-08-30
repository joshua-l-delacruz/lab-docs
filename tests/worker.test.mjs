import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import worker, {
  ApiError,
  MAX_REQUEST_BYTES,
  PLAN_LIMITS,
  API_SECURITY_HEADERS,
  HOME_SECURITY_HEADERS,
  LIVE_APPLICATION_ORIGINS,
  SECURITY_HEADERS,
  hasSameOrigin,
  limitsFor,
  normalizeDeal,
  proxyLiveApplication,
  readJson,
  secureResponse
} from "../worker/index.js";

const jsonRequest = (body, headers = {}) => new Request("https://example.com/api/v2/deals", {
  method: "POST",
  headers: { "content-type": "application/json", origin: "https://example.com", ...headers },
  body
});

test("accepts a valid JSON object", async () => {
  assert.deepEqual(await readJson(jsonRequest('{"title":"Deal"}')), { title: "Deal" });
});

test("rejects malformed JSON as a client error", async () => {
  await assert.rejects(
    readJson(jsonRequest("{")),
    error => error instanceof ApiError && error.status === 400 && error.code === "INVALID_JSON"
  );
});

test("rejects non-JSON media types", async () => {
  const request = new Request("https://example.com/api/v2/deals", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "title=Deal"
  });
  await assert.rejects(
    readJson(request),
    error => error instanceof ApiError && error.status === 415
  );
});

test("rejects request bodies larger than 256 KB", async () => {
  const request = jsonRequest(JSON.stringify({ value: "x".repeat(MAX_REQUEST_BYTES) }));
  await assert.rejects(
    readJson(request),
    error => error instanceof ApiError && error.status === 413 && error.code === "PAYLOAD_TOO_LARGE"
  );
});

test("requires a deal title with a 400 error", () => {
  assert.throws(
    () => normalizeDeal({ clientName: "Client" }, "deal-id"),
    error => error instanceof ApiError && error.status === 400 && error.code === "INVALID_DEAL"
  );
});

test("uses bounded active and total plan limits", () => {
  assert.deepEqual(limitsFor({ plan: "free" }), PLAN_LIMITS.free);
  assert.deepEqual(limitsFor({ plan: "professional" }), PLAN_LIMITS.professional);
  assert.equal(PLAN_LIMITS.free.active, 10);
  assert.equal(PLAN_LIMITS.free.total, 50);
});

test("accepts only exact same-origin mutations", () => {
  assert.equal(hasSameOrigin(jsonRequest("{}")), true);
  assert.equal(hasSameOrigin(jsonRequest("{}", { origin: "https://attacker.example" })), false);
});

test("source keeps concurrency and reopen checks inside SQL writes", async () => {
  const source = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");
  assert.match(source, /AND \(\? = '' OR updated_at = \?\)/);
  assert.match(source, /SELECT COUNT\(\*\) FROM deals WHERE owner_id = \? AND archived = 0/);
  assert.match(source, /STORAGE_LIMIT_REACHED/);
  assert.match(source, /version: "2\.1\.1"/);
});


test("applies the site-wide browser security policy", async () => {
  const secured = secureResponse(
    new Response("<!doctype html>", {
      headers: { "content-type": "text/html; charset=utf-8" }
    })
  );

  assert.equal(secured.headers.get("x-content-type-options"), "nosniff");
  assert.equal(secured.headers.get("x-frame-options"), "DENY");
  assert.equal(secured.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
  assert.match(secured.headers.get("strict-transport-security"), /max-age=63072000/);
  assert.match(secured.headers.get("permissions-policy"), /geolocation=\(self\)/);
  assert.match(secured.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.match(secured.headers.get("content-security-policy"), /object-src 'none'/);
  assert.match(secured.headers.get("content-security-policy"), /https:\/\/psgc\.cloud/);
  assert.equal(await secured.text(), "<!doctype html>");
});

test("security policy keeps sensitive capabilities disabled", () => {
  assert.match(SECURITY_HEADERS["permissions-policy"], /camera=\(\)/);
  assert.match(SECURITY_HEADERS["permissions-policy"], /microphone=\(\)/);
  assert.match(SECURITY_HEADERS["permissions-policy"], /payment=\(\)/);
  assert.match(SECURITY_HEADERS["permissions-policy"], /usb=\(\)/);
});


test("uses a locked-down CSP for JSON API responses", () => {
  assert.equal(
    API_SECURITY_HEADERS["content-security-policy"],
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'"
  );
  assert.doesNotMatch(API_SECURITY_HEADERS["content-security-policy"], /unsafe-inline|data:|https:/);
  assert.equal(SECURITY_HEADERS["strict-transport-security"], "max-age=63072000; includeSubDomains; preload");
});


test("homepage uses external assets and a strict CSP", async () => {
  const homepage = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(homepage, /href="\/assets\/css\/home\.css\?v=2"/);
  assert.match(homepage, /src="\/assets\/js\/home\.js\?v=1"/);
  assert.doesNotMatch(homepage, /<style[\s>]/i);
  assert.doesNotMatch(homepage, /\sstyle=/i);
  assert.doesNotMatch(homepage, /<script(?![^>]*(?:\bsrc=|type="application\/ld\+json"))[^>]*>/i);
  assert.match(homepage, /<script type="application\/ld\+json">/);
  assert.match(HOME_SECURITY_HEADERS["content-security-policy"], /sha256-XLuFGznggQHklfN0GjPo7D\/tFTj3zUFGF3GyJh9g2OE=/);
  assert.match(HOME_SECURITY_HEADERS["content-security-policy"], /script-src 'self'/);
  assert.match(HOME_SECURITY_HEADERS["content-security-policy"], /style-src 'self'/);
  assert.doesNotMatch(HOME_SECURITY_HEADERS["content-security-policy"], /unsafe-inline/);
});

test("homepage publishes complete search and social metadata", async () => {
  const homepage = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(homepage, /rel="canonical" href="https:\/\/joshuadelacruz\.solutions\/"/);
  assert.match(homepage, /name="robots" content="index,follow,max-image-preview:large/);
  assert.match(homepage, /property="og:image"/);
  assert.match(homepage, /name="twitter:card" content="summary_large_image"/);
  assert.match(homepage, /"@type":"Person"/);
  assert.match(homepage, /"@type":"WebSite"/);
  assert.match(homepage, /https:\/\/roadrush\.joshuadelacruz\.solutions\//);
  assert.match(homepage, /luzon-road-rush\.svg/);
});

test("publishes crawler discovery and web app files", async () => {
  const robots = await readFile(new URL("../robots.txt", import.meta.url), "utf8");
  const sitemap = await readFile(new URL("../sitemap.xml", import.meta.url), "utf8");
  const manifest = JSON.parse(await readFile(new URL("../site.webmanifest", import.meta.url), "utf8"));
  assert.match(robots, /Sitemap: https:\/\/joshuadelacruz\.solutions\/sitemap\.xml/);
  assert.match(sitemap, /<loc>https:\/\/joshuadelacruz\.solutions\/<\/loc>/);
  assert.equal(manifest.start_url, "/");
  assert.equal(manifest.icons[0].src, "/favicon.svg");
});

test("redirects www requests to the canonical host", async () => {
  const response = await worker.fetch(
    new Request("https://www.joshuadelacruz.solutions/workspaces/?source=test"),
    { ASSETS: { fetch: () => new Response("unexpected") } },
    {}
  );
  assert.equal(response.status, 308);
  assert.equal(response.headers.get("location"), "https://joshuadelacruz.solutions/workspaces/?source=test");
});

test("retires the services page without breaking its existing URLs", async () => {
  for (const pathname of ["/services", "/services/", "/services/index.html"]) {
    const response = await worker.fetch(
      new Request(`https://joshuadelacruz.solutions${pathname}`),
      { ASSETS: { fetch: () => new Response("unexpected") } },
      {}
    );
    assert.equal(response.status, 308);
    assert.equal(response.headers.get("location"), "https://joshuadelacruz.solutions/#contact");
  }
});

test("declares every branded custom domain and live application origin", async () => {
  const config = await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8");
  assert.match(config, /"pattern": "joshuadelacruz\.solutions"/);
  assert.match(config, /"pattern": "www\.joshuadelacruz\.solutions"/);
  assert.match(config, /"pattern": "calculator\.joshuadelacruz\.solutions"/);
  assert.match(config, /"pattern": "malware\.joshuadelacruz\.solutions"/);
  assert.match(config, /"pattern": "spending\.joshuadelacruz\.solutions"/);
  assert.equal(LIVE_APPLICATION_ORIGINS["calculator.joshuadelacruz.solutions"], "https://scientific-calculator-cpp.onrender.com");
  assert.equal(LIVE_APPLICATION_ORIGINS["malware.joshuadelacruz.solutions"], "https://global-malware-trends-cpp.onrender.com");
  assert.equal(LIVE_APPLICATION_ORIGINS["spending.joshuadelacruz.solutions"], "https://monthly-spending.vercel.app");
});

test("proxies branded application paths and rewrites origin redirects", async () => {
  let receivedRequest;
  const response = await proxyLiveApplication(
    new Request("https://calculator.joshuadelacruz.solutions/api/health?full=1"),
    new URL("https://calculator.joshuadelacruz.solutions/api/health?full=1"),
    "https://scientific-calculator-cpp.onrender.com",
    request => {
      receivedRequest = request;
      return new Response(null, {
        status: 302,
        headers: { location: "https://scientific-calculator-cpp.onrender.com/login?next=%2Fapi%2Fhealth" }
      });
    }
  );

  assert.equal(receivedRequest.url, "https://scientific-calculator-cpp.onrender.com/api/health?full=1");
  assert.equal(response.headers.get("location"), "https://calculator.joshuadelacruz.solutions/login?next=%2Fapi%2Fhealth");
});

test("public project CTAs use branded domains instead of deployment hostnames", async () => {
  const pages = await Promise.all([
    "../index.html",
    "../workspaces/index.html",
    "../cpp-calculator/index.html"
  ].map(path => readFile(new URL(path, import.meta.url), "utf8")));
  const markup = pages.join("\n");

  assert.match(markup, /https:\/\/calculator\.joshuadelacruz\.solutions\//);
  assert.match(markup, /https:\/\/malware\.joshuadelacruz\.solutions\//);
  assert.match(markup, /https:\/\/spending\.joshuadelacruz\.solutions\//);
  assert.doesNotMatch(markup, /https:\/\/scientific-calculator-cpp\.onrender\.com\//);
  assert.doesNotMatch(markup, /https:\/\/global-malware-trends-cpp\.onrender\.com\//);
  assert.doesNotMatch(markup, /https:\/\/monthly-spending\.vercel\.app\//);
});

test("workspaces lists every current public application", async () => {
  const page = await readFile(new URL("../workspaces/index.html", import.meta.url), "utf8");
  for (const project of [
    "PH Property Transaction Workspace",
    "Pi Monthly Spending",
    "Pi 2048 Network Game",
    "Luzon Road Rush",
    "IAM Support Automation &amp; Human Escalation",
    "C++ Scientific &amp; Programmer Calculator",
    "Global Malware Trends"
  ]) {
    assert.match(page, new RegExp(project.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(page, /https:\/\/spending\.joshuadelacruz\.solutions\//);
  assert.match(page, /https:\/\/roadrush\.joshuadelacruz\.solutions\//);
  assert.match(page, /monthly-spending\.svg/);
  assert.match(page, /luzon-road-rush\.svg/);
});

test("adds an explicit UTF-8 charset to HTML responses", () => {
  const secured = secureResponse(new Response("home", { headers: { "content-type": "text/html" } }));
  assert.equal(secured.headers.get("content-type"), "text/html; charset=utf-8");
});

test("strict homepage policy can be applied without changing other pages", () => {
  const secured = secureResponse(new Response("home"), HOME_SECURITY_HEADERS);
  assert.equal(
    secured.headers.get("content-security-policy"),
    HOME_SECURITY_HEADERS["content-security-policy"]
  );
  assert.match(SECURITY_HEADERS["content-security-policy"], /unsafe-inline/);
});


test("C++ case study uses external assets and a strict CSP", async () => {
  const page = await readFile(new URL("../cpp-calculator/index.html", import.meta.url), "utf8");
  const source = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");

  assert.match(page, /href="\/assets\/css\/cpp-calculator\.css\?v=1"/);
  assert.match(page, /src="\/assets\/js\/cpp-calculator\.js\?v=1"/);
  assert.doesNotMatch(page, /<style[\s>]/i);
  assert.doesNotMatch(page, /\sstyle=/i);
  assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.match(source, /url\.pathname === "\/cpp-calculator\/"/);
  assert.doesNotMatch(HOME_SECURITY_HEADERS["content-security-policy"], /unsafe-inline/);
});

test("portfolio pages no longer advertise freelance services or pricing", async () => {
  const pages = await Promise.all([
    "../index.html",
    "../workspaces/index.html"
  ].map(path => readFile(new URL(path, import.meta.url), "utf8")));
  const markup = pages.join("\n");
  assert.doesNotMatch(markup, /Hire Me|Request a Quote|fixed-price package/i);
  assert.doesNotMatch(markup, /href="\/services\/?/i);
  assert.match(markup, /mailto:josh\.delacruz19@gmail\.com/);
});
