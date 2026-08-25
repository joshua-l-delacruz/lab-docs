import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  ApiError,
  MAX_REQUEST_BYTES,
  PLAN_LIMITS,
  API_SECURITY_HEADERS,
  HOME_SECURITY_HEADERS,
  SECURITY_HEADERS,
  hasSameOrigin,
  limitsFor,
  normalizeDeal,
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
  assert.equal(SECURITY_HEADERS["strict-transport-security"], "max-age=63072000; includeSubDomains");
});


test("homepage uses external assets and a strict CSP", async () => {
  const homepage = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(homepage, /href="\/assets\/css\/home\.css\?v=2"/);
  assert.match(homepage, /src="\/assets\/js\/home\.js\?v=1"/);
  assert.doesNotMatch(homepage, /<style[\s>]/i);
  assert.doesNotMatch(homepage, /\sstyle=/i);
  assert.doesNotMatch(homepage, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.match(HOME_SECURITY_HEADERS["content-security-policy"], /script-src 'self'/);
  assert.match(HOME_SECURITY_HEADERS["content-security-policy"], /style-src 'self'/);
  assert.doesNotMatch(HOME_SECURITY_HEADERS["content-security-policy"], /unsafe-inline/);
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

test("services page presents scoped packages and uses a strict CSP", async () => {
  const page = await readFile(new URL("../services/index.html", import.meta.url), "utf8");
  const source = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");

  assert.match(page, /href="\/assets\/css\/services\.css\?v=1"/);
  assert.match(page, /src="\/assets\/js\/services\.js\?v=1"/);
  assert.doesNotMatch(page, /<style[\s>]/i);
  assert.doesNotMatch(page, /\sstyle=/i);
  assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.match(source, /url\.pathname === "\/services\/"/);
  assert.match(page, /Portfolio \/ Landing Page/);
  assert.match(page, /Interactive Business Tool/);
  assert.match(page, /Full-Stack Web Application/);
  assert.match(page, /30–50% deposit/);
  assert.match(page, /name="email"/);
  assert.match(page, /Request a Quote/);
  assert.match(page, /realestate-workspace\.png/);
  assert.match(page, /cpp-calculator-dashboard\.png/);
  assert.match(page, /global-malware-trends-dashboard\.png/);
  assert.doesNotMatch(HOME_SECURITY_HEADERS["content-security-policy"], /unsafe-inline/);
});

test("security portfolio presents evidence-backed role alignment and uses a strict CSP", async () => {
  const page = await readFile(
    new URL("../security/index.html", import.meta.url),
    "utf8",
  );
  const source = await readFile(
    new URL("../worker/index.js", import.meta.url),
    "utf8",
  );

  assert.match(page, /Senior IAM Analyst/);
  assert.match(
    page,
    /does not represent prior employment under a Security Architect title/,
  );
  assert.match(page, /href="\/assets\/css\/security\.css\?v=1"/);
  assert.match(page, /src="\/assets\/js\/home\.js\?v=1"/);
  assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)/i);
  assert.doesNotMatch(page, /\sstyle="/i);
  assert.match(source, /url\.pathname === "\/security\/"/);
  assert.doesNotMatch(
    HOME_SECURITY_HEADERS["content-security-policy"],
    /unsafe-inline/,
  );
});
