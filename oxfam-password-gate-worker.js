// Cloudflare Worker: password-gates access to the Oxfam order form, AND
// brokers every Supabase read/write the app needs through explicit,
// validated /api/* endpoints (see API SECURITY MODEL below).
//
// The real static pages (index.html, dashboard.html, picking.html) live on
// Cloudflare Pages (auto-deployed from the same GitHub repo). This Worker
// sits in front of it, asks for a shared password once, then proxies
// authenticated page requests through - and now ALSO handles /api/* calls
// itself using a Supabase service_role key that never leaves this Worker.
//
// SECURITY MODEL (read this before deploying):
//   This Worker only protects people who go through the Worker's URL.
//   By itself it does NOT stop someone from hitting the Pages origin
//   (https://oxfam-bon-de-commande.pages.dev) directly - Cloudflare
//   Pages projects are always publicly reachable at their *.pages.dev
//   address, there is no code-level way to disable that from here.
//   Closing that hole requires a Cloudflare Access "self-hosted
//   application" + "service token" set up in the dashboard - see the
//   deployment doc for the exact steps. This script supports that setup
//   (it will attach the service token to its origin requests if
//   CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET are configured) but
//   cannot create the Access application itself.
//
// API SECURITY MODEL (read this before deploying):
//   /api/* is NOT a generic Supabase proxy. There are exactly six routes
//   (POST /api/orders, GET /api/orders, GET /api/orders/:id,
//   GET /api/order-lines, POST /api/edit-order, POST /api/submit-picking).
//   Every other /api/* path 404s. The browser can never supply a table
//   name, REST path, SQL filter, or HTTP method that gets forwarded to
//   Supabase - each handler builds its own fixed Supabase request and only
//   ever inserts pre-validated values (a UUID matched against a regex, or
//   fields checked for type/length/range) into it.
//
//   Every /api/* route requires the same login cookie as the rest of the
//   site - there is no separate/weaker auth path for the API.
//
//   All Supabase access from these endpoints uses the SUPABASE_SERVICE_ROLE_KEY
//   secret, which bypasses Row Level Security. That's intentional: RLS is
//   now configured to deny the public anon key everything, and this Worker
//   is the only trusted server-side caller. The service_role key is read
//   once per request from `env` (a Cloudflare Secret) and is never written
//   into a response body, a log line visible to the client, or an error
//   message - Supabase error bodies/URLs are swallowed server-side
//   (console.error, which only appears in the Worker's own dashboard logs)
//   and replaced with a short generic error code before being returned.
//
// SETUP (in the Cloudflare dashboard):
//   1. Workers & Pages -> this worker -> Settings -> Variables and Secrets.
//      Add these as type "Secret" (NOT "Text"/plaintext env var):
//        SITE_PASSWORD               = the password shops type in
//        COOKIE_SECRET                = a long random string, DIFFERENT
//                                        from SITE_PASSWORD (required -
//                                        this Worker refuses to start
//                                        without it)
//        SUPABASE_SERVICE_ROLE_KEY    = the Supabase project's service_role
//                                        key (Supabase dashboard -> Project
//                                        Settings -> API -> service_role).
//                                        NEVER put this in anything that
//                                        ships to the browser.
//        EDIT_PASSCODE                = the shared passcode shops use to
//                                        edit an existing order (same value
//                                        that used to live on the Supabase
//                                        edit-order Edge Function - move it
//                                        here, this Worker now does that
//                                        job)
//        CF_ACCESS_CLIENT_ID          = (optional, only once Access is
//        CF_ACCESS_CLIENT_SECRET        set up) service token credentials
//                                        used to reach the now-locked-down
//                                        Pages origin
//   2. Settings -> Bindings -> Add -> Rate Limiting.
//        a) Variable name: LOGIN_RATE_LIMITER
//           Namespace ID: any unused integer, e.g. 1001
//           Limit: 8 requests / Period: 60 seconds
//        b) Variable name: WRITE_RATE_LIMITER (recommended, optional)
//           Namespace ID: any other unused integer, e.g. 1002
//           Limit: 20 requests / Period: 60 seconds
//      (If a binding isn't configured, the Worker still works, it just
//      skips that particular throttle - so add both.)
//   3. Save and deploy.
//
// To change the password later: update the SITE_PASSWORD secret and
// redeploy. That invalidates every existing cookie (expected).

const ORIGIN = "https://oxfam-bon-de-commande.pages.dev";
const COOKIE_NAME = "oxfam_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const LOGIN_RATE_LIMIT_KEY_PREFIX = "login:";
const WRITE_RATE_LIMIT_KEY_PREFIX = "write:";

const SUPABASE_URL = "https://ubqshzvbsqfekziyqxyc.supabase.co";
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const MAX_BODY_BYTES = 500_000; // 500 KB - generous for form_snapshot, blocks abuse

// TEMPORARY go-live safety net (2026-09-16, per Manu): CC'd on the picking
// écart email (see apiSubmitPicking) so he can monitor real sends during
// the rollout. Remove once he confirms the live flow is working as expected.
const DEV_COPY_EMAIL = "emmanuel.cossee@oxfam.org";

// ---- crypto helpers ---------------------------------------------------

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Constant-time string comparison. Both inputs here are always
// fixed-length HMAC-SHA256 digests (never raw secrets), so this removes
// any length- or content-based timing side channel from both the
// password check and the cookie check.
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const len = Math.max(a.length, b.length);
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

// ---- security headers ---------------------------------------------------

const CSP = [
  "default-src 'self'",
  // The app's JS/CSS is all inline (no build step), so 'unsafe-inline' is
  // required here or the whole app breaks. Everything else is locked down.
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "img-src 'self' data:",
  "font-src 'self' https://cdnjs.cloudflare.com",
  // All order data (orders/order_lines) now goes through this Worker's own
  // /api/* routes (same-origin, covered by 'self') - the browser holds no
  // Supabase key that can reach that data anymore. The one remaining
  // exception is index.html's live Odoo stock lookup (odoo-stock Edge
  // Function): non-sensitive, read-only, no order data, kept direct to
  // avoid adding yet another proxy route for something with nothing to
  // protect. Do NOT widen this for anything that touches orders/order_lines.
  "connect-src 'self' https://ubqshzvbsqfekziyqxyc.supabase.co",
  "frame-src https://formsubmit.co",
  "form-action 'self' https://formsubmit.co",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
].join("; ");

function withSecurityHeaders(resp, { noStore = false } = {}) {
  const headers = new Headers(resp.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
  headers.set("Content-Security-Policy", CSP);
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // Deliberately no Access-Control-Allow-Origin header anywhere in this
  // Worker: this app is a first-party page, not a cross-origin API, so
  // the browser's default same-origin policy is the correct behaviour.
  if (noStore) headers.set("Cache-Control", "no-store");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// ---- login page ---------------------------------------------------

function loginPage(showError, rateLimited) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acces protege / Beveiligde toegang</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f4f4f4; }
  form { background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); max-width: 320px; width: 100%; }
  h1 { font-size: 1.1rem; margin-top: 0; font-weight: 600; }
  input[type=password] { width: 100%; padding: 0.6rem; box-sizing: border-box; margin: 0.75rem 0; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
  button { width: 100%; padding: 0.6rem; background: #0072ce; color: #fff; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
  button:hover { background: #005ea3; }
  button:disabled { background: #999; cursor: not-allowed; }
  .error { color: #c00; font-size: 0.9rem; margin: 0 0 0.5rem 0; }
</style>
</head>
<body>
<form method="POST" action="/__login">
  <h1>Bon de commande Oxfam<br>Mot de passe requis / Wachtwoord vereist</h1>
  ${rateLimited ? `<p class="error">Trop de tentatives, reessayez dans une minute. / Te veel pogingen, probeer over een minuut opnieuw.</p>` : ""}
  ${showError && !rateLimited ? `<p class="error">Mot de passe incorrect. / Onjuist wachtwoord.</p>` : ""}
  <input type="password" name="password" placeholder="Mot de passe / Wachtwoord" autofocus required ${rateLimited ? "disabled" : ""}>
  <button type="submit" ${rateLimited ? "disabled" : ""}>Entrer / Binnengaan</button>
</form>
</body>
</html>`;
}

function htmlResponse(body, status) {
  return withSecurityHeaders(
    new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8" } }),
    { noStore: true }
  );
}

// ---- API helpers ---------------------------------------------------

// Thrown by validators/handlers to short-circuit with a clean response.
// `status` + `code` only - never a raw error object, Supabase body, or
// stack trace reaches the client.
function apiFail(status, code) {
  return { __apiError: true, status, code };
}

function apiJson(body, status) {
  return withSecurityHeaders(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
    { noStore: true }
  );
}

function apiError(status, code) {
  return apiJson({ error: code }, status);
}

async function readJsonBody(request) {
  const len = request.headers.get("content-length");
  if (len && Number(len) > MAX_BODY_BYTES) throw apiFail(413, "payload_too_large");
  let text;
  try {
    text = await request.text();
  } catch (e) {
    throw apiFail(400, "invalid_body");
  }
  if (text.length > MAX_BODY_BYTES) throw apiFail(413, "payload_too_large");
  try {
    return JSON.parse(text);
  } catch (e) {
    throw apiFail(400, "invalid_json");
  }
}

// ---- input validation ---------------------------------------------------

function isUuid(v) {
  return typeof v === "string" && UUID_RE.test(v);
}
function isNonEmptyString(v, maxLen) {
  return typeof v === "string" && v.trim().length > 0 && v.length <= maxLen;
}
function isOptString(v, maxLen) {
  return v === null || v === undefined || (typeof v === "string" && v.length <= maxLen);
}
function isOptNumber(v, min, max) {
  if (v === null || v === undefined || v === "") return true;
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) && n >= min && n <= max;
}
function numOrNull(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = typeof v === "string" ? Number(v) : v;
  return Number.isFinite(n) ? n : null;
}

// Only ever reads known fields off `input` - anything else the browser
// sends is silently dropped, never forwarded to Supabase.
function sanitizeOrderPayload(input) {
  if (!input || typeof input !== "object") throw apiFail(400, "invalid_order");

  if (!isNonEmptyString(input.store_name, 200)) throw apiFail(400, "invalid_store_name");
  if (!(input.delivery_date === null || input.delivery_date === undefined || input.delivery_date === "" ||
        (typeof input.delivery_date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(input.delivery_date))))
    throw apiFail(400, "invalid_delivery_date");
  if (!isOptString(input.want_delivery, 50)) throw apiFail(400, "invalid_want_delivery");
  if (!isOptString(input.want_transfer, 50)) throw apiFail(400, "invalid_want_transfer");
  if (!isOptString(input.want_return, 50)) throw apiFail(400, "invalid_want_return");
  if (!isOptNumber(input.nb_chariots, 0, 100000)) throw apiFail(400, "invalid_nb_chariots");
  if (!isOptNumber(input.nb_bacs_it, 0, 100000)) throw apiFail(400, "invalid_nb_bacs_it");
  if (!isOptNumber(input.nb_sacs_monnaie, 0, 100000)) throw apiFail(400, "invalid_nb_sacs_monnaie");
  if (!isOptNumber(input.nb_cartons_livres, 0, 100000)) throw apiFail(400, "invalid_nb_cartons_livres");
  if (!isOptNumber(input.nb_bacs_jaunes, 0, 100000)) throw apiFail(400, "invalid_nb_bacs_jaunes");
  if (input.farde_compta !== undefined && input.farde_compta !== null && typeof input.farde_compta !== "boolean")
    throw apiFail(400, "invalid_farde_compta");
  if (input.vidange_oft !== undefined && input.vidange_oft !== null && typeof input.vidange_oft !== "boolean")
    throw apiFail(400, "invalid_vidange_oft");
  if (!isOptString(input.remarques_logistique, 5000)) throw apiFail(400, "invalid_remarques_logistique");
  if (!isOptString(input.locale, 10)) throw apiFail(400, "invalid_locale");
  if (input.form_snapshot !== undefined && input.form_snapshot !== null) {
    if (typeof input.form_snapshot !== "object") throw apiFail(400, "invalid_form_snapshot");
    let size = 0;
    try { size = JSON.stringify(input.form_snapshot).length; } catch (e) { throw apiFail(400, "invalid_form_snapshot"); }
    if (size > 300000) throw apiFail(400, "form_snapshot_too_large");
  }

  return {
    store_name: input.store_name.trim(),
    delivery_date: input.delivery_date || null,
    want_delivery: input.want_delivery || null,
    want_transfer: input.want_transfer || null,
    want_return: input.want_return || null,
    nb_chariots: numOrNull(input.nb_chariots),
    nb_bacs_it: numOrNull(input.nb_bacs_it),
    nb_sacs_monnaie: numOrNull(input.nb_sacs_monnaie),
    nb_cartons_livres: numOrNull(input.nb_cartons_livres),
    nb_bacs_jaunes: numOrNull(input.nb_bacs_jaunes),
    farde_compta: !!input.farde_compta,
    vidange_oft: !!input.vidange_oft,
    remarques_logistique: input.remarques_logistique || null,
    form_snapshot: input.form_snapshot ?? null,
    locale: input.locale || null,
  };
}

function sanitizeLines(input) {
  if (input === undefined || input === null) return [];
  if (!Array.isArray(input)) throw apiFail(400, "invalid_lines");
  if (input.length > 1000) throw apiFail(400, "too_many_lines");
  return input.map((l) => {
    if (!l || typeof l !== "object") throw apiFail(400, "invalid_line");
    if (!isNonEmptyString(l.category, 200)) throw apiFail(400, "invalid_line_category");
    if (!isNonEmptyString(l.article_fr, 500)) throw apiFail(400, "invalid_line_article");
    if (!isOptString(l.article_nl, 500)) throw apiFail(400, "invalid_line_article_nl");
    const qty = typeof l.quantity === "string" ? Number(l.quantity) : l.quantity;
    if (typeof qty !== "number" || !Number.isFinite(qty) || qty <= 0 || qty > 100000)
      throw apiFail(400, "invalid_line_quantity");
    return {
      category: l.category.trim(),
      article_fr: l.article_fr.trim(),
      article_nl: l.article_nl ? l.article_nl.trim() : null,
      quantity: qty,
    };
  });
}

function sanitizePickingLines(input) {
  if (input === undefined || input === null) return [];
  if (!Array.isArray(input)) throw apiFail(400, "invalid_lines");
  if (input.length > 1000) throw apiFail(400, "too_many_lines");
  return input.map((l) => {
    if (!l || typeof l !== "object" || !isUuid(l.id)) throw apiFail(400, "invalid_line_id");
    let qp = l.quantity_picked;
    if (qp === "" || qp === undefined) qp = null;
    if (qp !== null) {
      qp = typeof qp === "string" ? Number(qp) : qp;
      if (typeof qp !== "number" || !Number.isFinite(qp) || qp < 0 || qp > 100000)
        throw apiFail(400, "invalid_line_quantity");
    }
    return { id: l.id, quantity_picked: qp };
  });
}

// ---- Supabase (service role) helpers ---------------------------------

function sbHeaders(env, extra) {
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  return Object.assign(
    {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
    },
    extra || {}
  );
}

// Every Supabase call in this Worker goes through this wrapper: on any
// non-2xx response or network error, the real status/body (which can
// include the Supabase project URL, SQL error text, or column names) is
// logged server-side only (console.error -> Worker logs, never sent to the
// client) and replaced with a short generic error code.
async function sbFetchOrThrow(path, init, genericCode) {
  let resp;
  try {
    resp = await fetch(`${SUPABASE_URL}${path}`, init);
  } catch (e) {
    console.error("supabase network error", path, String(e));
    throw apiFail(502, genericCode || "upstream_error");
  }
  if (!resp.ok) {
    let bodyText = "";
    try {
      bodyText = await resp.text();
    } catch (e) {
      /* ignore */
    }
    console.error("supabase error", path, resp.status, bodyText);
    throw apiFail(502, genericCode || "upstream_error");
  }
  return resp;
}

// ---- SHOP_EMAILS -------------------------------------------------------
// Same mapping as SHOP_EMAILS in index.html / the old submit-picking Edge
// Function - keep these in sync if a shop's email or name ever changes.
const SHOP_EMAILS = {
  "Shop Marolles": "Shop.Marolles@oxfam.org",
  "Shop Aalst Lange Zoutstraat": "shop.aalst@oxfam.org",
  "Shop Oostende": "Shop.Oostende@oxfam.org",
  "Bookshop Gent": "Bookshop.Gent@oxfam.org",
  "Shop Brugge": "Shop.Brugge@oxfam.org",
  "Bookshop Kortrijk": "Bookshop.Kortrijk@oxfam.org",
  "Shop Knokke-Heist": "Shop.Knokke-Heist@oxfam.org",
  "Shop Gent Steendam": "Shop.Gent@oxfam.org",
  "Shop Leuven Diestsestraat": "shop.leuven@oxfam.org",
  "Shop Antwerpen Lange Koertpoortstraat": "shop.antwerpen.noord@oxfam.org",
  "Shop Halle Volpestraat": "shop.halle@oxfam.org",
  "Shop Vilvoorde Leuvensestraat": "shop.vilvoorde@oxfam.org",
  "Shop Wilrijk": "Shop.Wilrijk@oxfam.org",
  "Shop Mechelen": "Shop.Mechelen@oxfam.org",
  "Boutique Antwerpen": "Boutique.Antwerpen@oxfam.org",
  "Bookshop Leuven": "Bookshop.Leuven@oxfam.org",
  "Bookshop Antwerpen": "Bookshop.Antwerpen@oxfam.org",
  "Shop Fléron": "Shop.Fleron@oxfam.org",
  "RE.BEL Féronstrée": "carine.demyttenaere@oxfam.org",
  "Shop Casquette": "Shop.Casquette@oxfam.org",
  "Shop Herstal Laixheau": "Shop.Herstal@oxfam.org",
  "Shop Herstal Zénobe-Gramme": "Shop.Herstal@oxfam.org",
  "Shop Outre-Meuse": "Shop.Outre-Meuse@oxfam.org",
  "Bookshop Liège": "Bookshop.Liege@oxfam.org",
  "Shop Namur Bomel": "Shop.Namur@oxfam.org",
  "Shop Dinant": "Shop.Dinant@oxfam.org",
  "Shop Mons Textile": "Shop.Mons.Textile@oxfamsol.be",
  "Shop Charleroi rue de la Montagne": "shop.charleroi@oxfam.org",
  "Shop Nivelles": "Shop.Nivelles@oxfam.org",
  "Bookshop Namur": "Bookshop.Namur@oxfam.org",
  "Shop Ciney": "Shop.Ciney@oxfam.org",
  "Shop Marcinelle": "Shop.Marcinelle@oxfam.org",
  "Computer & Bookshop Mons": "Shop.Mons@oxfam.org",
  "Shop Vintage": "shop.vintage@oxfam.org",
  "Shop Etterbeek": "shop.etterbeek@oxfam.org",
  "Bookshop Ixelles": "Bookshop.Ixelles@oxfam.org",
  "Shop Brabançonne": "Shop.Brabanconne@oxfam.org",
  "Computershop Ixelles": "ComputerShop.Ixelles@oxfam.org",
  "Bookshop Uccle": "Bookshop.Uccle@oxfam.org",
  "Shop Belgica": "Shop.Jette@oxfam.org",
};

// ---- /api/* endpoint handlers ---------------------------------------

async function apiCreateOrder(request, env) {
  const body = await readJsonBody(request);
  const order = sanitizeOrderPayload(body.order);
  const lines = sanitizeLines(body.lines);

  const insertResp = await sbFetchOrThrow(
    "/rest/v1/orders",
    { method: "POST", headers: sbHeaders(env, { Prefer: "return=representation" }), body: JSON.stringify(order) },
    "order_insert_failed"
  );
  const rows = await insertResp.json();
  const orderId = rows && rows[0] && rows[0].id;
  if (!orderId) throw apiFail(502, "order_insert_failed");

  if (lines.length) {
    const linesPayload = lines.map((l) => Object.assign({}, l, { order_id: orderId }));
    await sbFetchOrThrow(
      "/rest/v1/order_lines",
      { method: "POST", headers: sbHeaders(env, { Prefer: "return=minimal" }), body: JSON.stringify(linesPayload) },
      "lines_insert_failed"
    );
  }

  return apiJson({ id: orderId }, 200);
}

async function apiGetOrder(env, orderId) {
  if (!isUuid(orderId)) throw apiFail(400, "invalid_id");
  const resp = await sbFetchOrThrow(
    `/rest/v1/orders?id=eq.${orderId}&select=*`,
    { headers: sbHeaders(env) },
    "order_fetch_failed"
  );
  const rows = await resp.json();
  if (!rows.length) throw apiFail(404, "not_found");
  return apiJson(rows[0], 200);
}

async function apiListOrders(env) {
  const resp = await sbFetchOrThrow(
    "/rest/v1/orders?select=*&order=created_at.desc&limit=2000",
    { headers: sbHeaders(env) },
    "orders_fetch_failed"
  );
  const rows = await resp.json();
  return apiJson(rows, 200);
}

async function apiListOrderLines(env, orderIdParam) {
  let path;
  if (orderIdParam) {
    if (!isUuid(orderIdParam)) throw apiFail(400, "invalid_id");
    path = `/rest/v1/order_lines?order_id=eq.${orderIdParam}&select=*&order=category.asc`;
  } else {
    path = "/rest/v1/order_lines?select=*&limit=20000";
  }
  const resp = await sbFetchOrThrow(path, { headers: sbHeaders(env) }, "lines_fetch_failed");
  const rows = await resp.json();
  return apiJson(rows, 200);
}

async function apiEditOrder(request, env) {
  const body = await readJsonBody(request);
  if (!isUuid(body.orderId)) throw apiFail(400, "invalid_id");
  if (typeof body.passcode !== "string" || !body.passcode) throw apiFail(400, "missing_passcode");
  if (!env.EDIT_PASSCODE) {
    console.error("EDIT_PASSCODE secret is not configured");
    throw apiFail(500, "server_misconfigured");
  }

  // Same constant-time-compare trick used for the site password: never
  // compare raw strings, compare fixed-length HMAC digests of them.
  const gotDigest = await sign(body.passcode.trim(), env.COOKIE_SECRET);
  const wantDigest = await sign(env.EDIT_PASSCODE.trim(), env.COOKIE_SECRET);
  if (!constantTimeEqual(gotDigest, wantDigest)) throw apiFail(401, "invalid_passcode");

  const order = sanitizeOrderPayload(body.order);
  const lines = sanitizeLines(body.lines);

  await sbFetchOrThrow(
    `/rest/v1/orders?id=eq.${body.orderId}`,
    { method: "PATCH", headers: sbHeaders(env, { Prefer: "return=representation" }), body: JSON.stringify(order) },
    "order_update_failed"
  );

  await sbFetchOrThrow(
    `/rest/v1/order_lines?order_id=eq.${body.orderId}`,
    { method: "DELETE", headers: sbHeaders(env) },
    "lines_delete_failed"
  );

  if (lines.length) {
    const linesPayload = lines.map((l) => Object.assign({}, l, { order_id: body.orderId }));
    await sbFetchOrThrow(
      "/rest/v1/order_lines",
      { method: "POST", headers: sbHeaders(env, { Prefer: "return=minimal" }), body: JSON.stringify(linesPayload) },
      "lines_insert_failed"
    );
  }

  return apiJson({ ok: true, orderId: body.orderId }, 200);
}

async function apiSubmitPicking(request, env) {
  const body = await readJsonBody(request);
  if (!isUuid(body.orderId)) throw apiFail(400, "invalid_id");
  if (!isNonEmptyString(body.pickedBy, 200)) throw apiFail(400, "missing_picked_by");
  const lines = sanitizePickingLines(body.lines);

  const orderResp = await sbFetchOrThrow(
    `/rest/v1/orders?id=eq.${body.orderId}&select=id,store_name,delivery_date`,
    { headers: sbHeaders(env) },
    "order_fetch_failed"
  );
  const orderRows = await orderResp.json();
  if (!orderRows.length) throw apiFail(404, "not_found");
  const order = orderRows[0];

  const pickedBy = body.pickedBy.trim();

  const results = await Promise.all(
    lines.map(async (line) => {
      const lineResp = await sbFetchOrThrow(
        `/rest/v1/order_lines?id=eq.${line.id}`,
        {
          method: "PATCH",
          headers: sbHeaders(env, { Prefer: "return=representation" }),
          body: JSON.stringify({ quantity_picked: line.quantity_picked }),
        },
        "line_update_failed"
      );
      const updated = await lineResp.json();
      return updated[0];
    })
  );

  const diffs = results
    .filter((row) => row && parseFloat(row.quantity_picked) !== parseFloat(row.quantity))
    .map((row) => ({
      article: row.article_fr + (row.article_nl ? ` / ${row.article_nl}` : ""),
      ordered: row.quantity,
      picked: row.quantity_picked,
    }));

  await sbFetchOrThrow(
    `/rest/v1/orders?id=eq.${body.orderId}`,
    {
      method: "PATCH",
      headers: sbHeaders(env),
      body: JSON.stringify({ picking_completed_at: new Date().toISOString(), picked_by: pickedBy }),
    },
    "order_update_failed"
  );

  let emailSent = false;
  let emailError = null;
  if (diffs.length) {
    const shopEmail = SHOP_EMAILS[order.store_name];
    if (shopEmail) {
      const summary = diffs
        .map((d) => `${d.article} : commandé ${d.ordered} / prélevé ${d.picked}`)
        .join("\n");
      try {
        const emailResp = await fetch(`https://formsubmit.co/ajax/${shopEmail}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({
            _subject: `Écarts de préparation - ${order.store_name} - ${order.delivery_date}`,
            _template: "box",
            // TEMPORARY go-live safety net (2026-09-16, per Manu): CC every
            // écart email so he can monitor real sends during the rollout.
            // Remove DEV_COPY_EMAIL and this field once confirmed working.
            _cc: DEV_COPY_EMAIL,
            Magasin: order.store_name,
            "Date de livraison": order.delivery_date,
            "Préparé par": pickedBy,
            "Écarts (commandé / prélevé)": summary,
          }),
        });
        emailSent = emailResp.ok;
        if (!emailResp.ok) emailError = "email_failed";
      } catch (e) {
        console.error("formsubmit error", String(e));
        emailError = "email_failed";
      }
    } else {
      emailError = "no_email_on_file";
    }
  }

  return apiJson({ ok: true, diffCount: diffs.length, emailSent, emailError }, 200);
}

// ---- /api/* router ---------------------------------------------------
//
// Explicit whitelist. Six routes, nothing else. No path segment or query
// parameter here is ever passed to Supabase without going through one of
// the validators above first.
async function routeApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  if (env.WRITE_RATE_LIMITER && (method === "POST" || method === "PATCH" || method === "DELETE")) {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const { success } = await env.WRITE_RATE_LIMITER.limit({ key: WRITE_RATE_LIMIT_KEY_PREFIX + ip });
    if (!success) throw apiFail(429, "rate_limited");
  }

  if (path === "/api/orders" && method === "POST") return apiCreateOrder(request, env);
  if (path === "/api/orders" && method === "GET") return apiListOrders(env);

  const orderIdMatch = path.match(/^\/api\/orders\/([^/]+)$/);
  if (orderIdMatch && method === "GET") return apiGetOrder(env, decodeURIComponent(orderIdMatch[1]));

  if (path === "/api/order-lines" && method === "GET") {
    return apiListOrderLines(env, url.searchParams.get("order_id"));
  }

  if (path === "/api/edit-order" && method === "POST") return apiEditOrder(request, env);
  if (path === "/api/submit-picking" && method === "POST") return apiSubmitPicking(request, env);

  throw apiFail(404, "not_found");
}

async function handleApi(request, env, url) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("SUPABASE_SERVICE_ROLE_KEY secret is not configured");
    return apiError(500, "server_misconfigured");
  }
  try {
    return await routeApi(request, env, url);
  } catch (e) {
    if (e && e.__apiError) return apiError(e.status, e.code);
    console.error("unhandled api error", String(e && e.stack ? e.stack : e));
    return apiError(500, "internal_error");
  }
}

// ---- request handlers ---------------------------------------------------

async function handleLogout() {
  const headers = new Headers();
  headers.set("Location", "/");
  // Expire the cookie immediately, same attributes as when it was set
  // (browsers only delete a cookie if Path/attributes match).
  headers.append(
    "Set-Cookie",
    `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
  );
  return withSecurityHeaders(new Response(null, { status: 302, headers }), { noStore: true });
}

async function handleLogin(request, env, signSecret) {
  // Brute-force protection: cap login attempts per client IP. Applies to
  // every POST to /__login regardless of outcome.
  if (env.LOGIN_RATE_LIMITER) {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const { success } = await env.LOGIN_RATE_LIMITER.limit({ key: LOGIN_RATE_LIMIT_KEY_PREFIX + ip });
    if (!success) {
      return htmlResponse(loginPage(false, true), 429);
    }
  }

  const form = await request.formData();
  const submitted = (form.get("password") || "").toString();

  // Never compare the raw password with `===`. Comparing two fixed-length
  // HMAC digests in constant time removes both the timing side channel
  // and any length-based leak.
  const submittedDigest = await sign(submitted, signSecret);
  const expectedDigest = await sign(env.SITE_PASSWORD, signSecret);
  const ok = constantTimeEqual(submittedDigest, expectedDigest);

  if (ok) {
    const token = await sign("ok", signSecret);
    const headers = new Headers();
    headers.set("Location", "/");
    headers.append(
      "Set-Cookie",
      `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`
    );
    return withSecurityHeaders(new Response(null, { status: 302, headers }), { noStore: true });
  }

  return htmlResponse(loginPage(true, false), 401);
}

async function proxyToOrigin(request, url, env) {
  const originUrl = ORIGIN + url.pathname + url.search;
  const headers = new Headers();
  // Deliberately NOT forwarding the visitor's own request headers
  // (Cookie, Authorization, etc.) to the origin - the origin never needs
  // them, and forwarding them would leak this Worker's auth cookie
  // downstream. Only a minimal, explicit set of headers is sent.
  const acceptHeader = request.headers.get("Accept");
  if (acceptHeader) headers.set("Accept", acceptHeader);
  if (env.CF_ACCESS_CLIENT_ID && env.CF_ACCESS_CLIENT_SECRET) {
    // Required once the Pages origin is locked behind Cloudflare Access -
    // this is how the Worker itself (a non-interactive client) authenticates
    // to fetch the real content server-side.
    headers.set("CF-Access-Client-Id", env.CF_ACCESS_CLIENT_ID);
    headers.set("CF-Access-Client-Secret", env.CF_ACCESS_CLIENT_SECRET);
  }

  const originResp = await fetch(originUrl, {
    method: request.method,
    headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
  });

  // Authenticated app content still gets no-store: several shops share one
  // browser/device, and this avoids order data persisting in a shared
  // machine's disk/back-forward cache after someone logs out.
  return withSecurityHeaders(new Response(originResp.body, originResp), { noStore: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isApi = url.pathname === "/api" || url.pathname.startsWith("/api/");

    if (!env.SITE_PASSWORD) {
      return new Response("SITE_PASSWORD secret is not configured on this Worker.", { status: 500 });
    }
    if (!env.COOKIE_SECRET) {
      // Fail closed. The old behaviour of silently signing cookies with
      // SITE_PASSWORD itself is gone - if the cookie secret leaks (e.g. via
      // a forged/replayed cookie), it must not also hand over the login
      // password, and vice versa.
      return new Response(
        "COOKIE_SECRET secret is not configured on this Worker. Set it (as a Secret, not a plain variable) before this Worker can run.",
        { status: 500 }
      );
    }
    const signSecret = env.COOKIE_SECRET;

    if (url.pathname === "/__logout") {
      return handleLogout();
    }

    if (request.method === "POST" && url.pathname === "/__login") {
      return handleLogin(request, env, signSecret);
    }

    const cookieToken = getCookie(request, COOKIE_NAME);
    const expectedToken = await sign("ok", signSecret);
    const authed = !!cookieToken && constantTimeEqual(cookieToken, expectedToken);

    if (!authed) {
      // API calls get a clean JSON 401 (the frontend's fetch() calls check
      // resp.ok and show a toast); page navigations get the login page.
      if (isApi) return apiError(401, "unauthenticated");
      return htmlResponse(loginPage(false, false), 401);
    }

    if (isApi) {
      return handleApi(request, env, url);
    }

    return proxyToOrigin(request, url, env);
  },
};
