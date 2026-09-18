// Standalone functional test harness for oxfam-password-gate-worker.js.
// Mocks global fetch (Supabase + FormSubmit calls) and drives the exported
// `fetch` handler directly with fake Request objects and a fake `env`.
// Not a Cloudflare Workers runtime - just enough to exercise the routing,
// validation, auth-gating, and error-shape logic before deploying.

import assert from 'node:assert/strict';

const REAL_FETCH_CALLS = [];
const originalFetch = global.fetch;

// ---- fake env -----------------------------------------------------------
const env = {
  SITE_PASSWORD: 'test-site-password',
  COOKIE_SECRET: 'test-cookie-secret-abc123',
  SUPABASE_SERVICE_ROLE_KEY: 'FAKE_SERVICE_ROLE_KEY_SHOULD_NEVER_LEAK',
  EDIT_PASSCODE: 'edit-pass-123',
  // no rate limiters configured for most tests; a couple of tests add them
};

const worker = (await import('./oxfam-password-gate-worker.js')).default;

// ---- helpers to sign a valid auth cookie the same way the worker does ---
async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const validCookie = 'oxfam_auth=' + encodeURIComponent(await sign('ok', env.COOKIE_SECRET));

function req(path, { method = 'GET', cookie = null, body = null, headers = {} } = {}) {
  const h = new Headers(headers);
  if (cookie) h.set('Cookie', cookie);
  if (body !== null && !h.has('Content-Type')) h.set('Content-Type', 'application/json');
  return new Request('https://example.com' + path, {
    method,
    headers: h,
    body: body !== null ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
  });
}

let passed = 0, failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  ok -', name);
  } catch (e) {
    failed++;
    console.log('  FAIL -', name);
    console.log('   ', e.message);
  }
}

function mockFetch(handler) {
  global.fetch = async (url, init) => {
    REAL_FETCH_CALLS.push({ url: String(url), init });
    return handler(String(url), init);
  };
}

// ==========================================================================
console.log('1. Unauthenticated access');
await test('GET / without cookie -> 401 HTML login page (not JSON)', async () => {
  const resp = await worker.fetch(req('/'), env);
  assert.equal(resp.status, 401);
  const ct = resp.headers.get('Content-Type') || '';
  assert.ok(ct.includes('text/html'), 'expected html, got ' + ct);
});

await test('GET /api/orders without cookie -> 401 JSON {error:"unauthenticated"}', async () => {
  const resp = await worker.fetch(req('/api/orders'), env);
  assert.equal(resp.status, 401);
  const body = await resp.json();
  assert.equal(body.error, 'unauthenticated');
});

await test('POST /api/submit-picking without cookie -> 401', async () => {
  const resp = await worker.fetch(req('/api/submit-picking', { method: 'POST', body: {} }), env);
  assert.equal(resp.status, 401);
});

await test('GET /api/orders/<uuid> without cookie -> 401', async () => {
  const resp = await worker.fetch(req('/api/orders/11111111-1111-4111-8111-111111111111'), env);
  assert.equal(resp.status, 401);
});

console.log('2. Whitelisted routing / 404s');
await test('GET /api/whatever-else with valid cookie -> 404 not_found (no proxy)', async () => {
  mockFetch(async () => { throw new Error('should never call fetch for unknown api route'); });
  const resp = await worker.fetch(req('/api/whatever-else', { cookie: validCookie }), env);
  assert.equal(resp.status, 404);
  const body = await resp.json();
  assert.equal(body.error, 'not_found');
});

await test('POST /api/orders/<uuid> (wrong method for that path) -> 404, not forwarded', async () => {
  mockFetch(async () => { throw new Error('should not call supabase'); });
  const resp = await worker.fetch(req('/api/orders/11111111-1111-4111-8111-111111111111', { method: 'POST', cookie: validCookie, body: {} }), env);
  assert.equal(resp.status, 404);
});

console.log('3. POST /api/orders (create) validation + success path');
await test('valid order+lines -> 200 {id}, service_role key sent to supabase but never in response', async () => {
  mockFetch(async (url, init) => {
    if (url.includes('/rest/v1/orders') && init.method === 'POST') {
      assert.equal(init.headers.apikey, env.SUPABASE_SERVICE_ROLE_KEY);
      const sentBody = JSON.parse(init.body);
      // unexpected field must have been stripped before reaching supabase
      assert.equal(sentBody.__proto__constructor, undefined);
      assert.equal(Object.prototype.hasOwnProperty.call(sentBody, 'evil_field'), false);
      assert.equal(sentBody.store_name, 'Shop Marolles');
      return new Response(JSON.stringify([{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }]), { status: 201 });
    }
    if (url.includes('/rest/v1/order_lines') && init.method === 'POST') {
      const sentLines = JSON.parse(init.body);
      assert.equal(sentLines.length, 1);
      assert.equal(sentLines[0].order_id, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
      return new Response(null, { status: 201 });
    }
    throw new Error('unexpected fetch ' + url);
  });
  const resp = await worker.fetch(req('/api/orders', {
    method: 'POST', cookie: validCookie,
    body: {
      order: { store_name: 'Shop Marolles', evil_field: 'DROP TABLE orders', delivery_date: '2026-01-01' },
      lines: [{ category: 'Cat', article_fr: 'Article', article_nl: '', quantity: 3 }],
    },
  }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.id, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
  const respText = JSON.stringify(body);
  assert.ok(!respText.includes(env.SUPABASE_SERVICE_ROLE_KEY), 'service role key leaked into response!');
});

await test('missing store_name -> 400 invalid_store_name, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders', { method: 'POST', cookie: validCookie, body: { order: {}, lines: [] } }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'invalid_store_name');
});

await test('bad line quantity (0) -> 400 invalid_line_quantity', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders', {
    method: 'POST', cookie: validCookie,
    body: { order: { store_name: 'Shop Marolles' }, lines: [{ category: 'c', article_fr: 'a', quantity: 0 }] },
  }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'invalid_line_quantity');
});

await test('store_name not in the real shop list -> 400 unknown_store_name, supabase never called (Sept 2026 fix)', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders', {
    method: 'POST', cookie: validCookie,
    body: { order: { store_name: '<img src=x onerror=alert(1)>', delivery_date: '2026-01-01' }, lines: [] },
  }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'unknown_store_name');
});

await test('malformed JSON body -> 400 invalid_json', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders', { method: 'POST', cookie: validCookie, body: '{not json' }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'invalid_json');
});

await test('oversized body (Content-Length lie) -> 413 payload_too_large', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders', {
    method: 'POST', cookie: validCookie, body: { order: { store_name: 'x' } },
    headers: { 'Content-Length': String(10_000_000) },
  }), env);
  assert.equal(resp.status, 413);
});

console.log('4. GET /api/orders/:id');
await test('malformed uuid -> 400 invalid_id, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/orders/not-a-uuid', { cookie: validCookie }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'invalid_id');
});

await test('valid uuid, not found in supabase -> 404 not_found (no supabase details leaked)', async () => {
  mockFetch(async () => new Response(JSON.stringify([]), { status: 200 }));
  const resp = await worker.fetch(req('/api/orders/11111111-1111-4111-8111-111111111111', { cookie: validCookie }), env);
  assert.equal(resp.status, 404);
  const body = await resp.json();
  assert.equal(body.error, 'not_found');
});

await test('supabase 500s -> generic 502 upstream error, no supabase URL/body leaked', async () => {
  mockFetch(async () => new Response('duplicate key value violates constraint orders_pkey on table "orders"', { status: 500 }));
  const resp = await worker.fetch(req('/api/orders/11111111-1111-4111-8111-111111111111', { cookie: validCookie }), env);
  assert.equal(resp.status, 502);
  const body = await resp.json();
  assert.equal(body.error, 'order_fetch_failed');
  const text = JSON.stringify(body);
  assert.ok(!text.includes('supabase'), 'leaked supabase reference');
  assert.ok(!text.includes('orders_pkey'), 'leaked db constraint name');
});

console.log('5. GET /api/order-lines (bulk for dashboard, scoped for picking)');
await test('no order_id -> bulk query, limit=20000', async () => {
  mockFetch(async (url) => {
    assert.ok(url.includes('limit=20000'));
    assert.ok(!url.includes('order_id'));
    return new Response(JSON.stringify([{ id: '1' }]), { status: 200 });
  });
  const resp = await worker.fetch(req('/api/order-lines', { cookie: validCookie }), env);
  assert.equal(resp.status, 200);
});

await test('with valid order_id -> scoped query', async () => {
  mockFetch(async (url) => {
    assert.ok(url.includes('order_id=eq.11111111-1111-4111-8111-111111111111'));
    return new Response(JSON.stringify([]), { status: 200 });
  });
  const resp = await worker.fetch(req('/api/order-lines?order_id=11111111-1111-4111-8111-111111111111', { cookie: validCookie }), env);
  assert.equal(resp.status, 200);
});

await test('with malformed order_id -> 400, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/order-lines?order_id=DROP+TABLE', { cookie: validCookie }), env);
  assert.equal(resp.status, 400);
});

console.log('6. POST /api/edit-order');
await test('wrong passcode -> 401 invalid_passcode, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/edit-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', passcode: 'wrong', order: { store_name: 'x' }, lines: [] },
  }), env);
  assert.equal(resp.status, 401);
  const body = await resp.json();
  assert.equal(body.error, 'invalid_passcode');
});

await test('correct passcode -> patches order, deletes+reinserts lines -> 200 ok', async () => {
  const calls = [];
  mockFetch(async (url, init) => {
    calls.push({ url, method: init.method });
    if (url.includes('/rest/v1/orders?id=eq.') && init.method === 'PATCH') return new Response('[]', { status: 200 });
    if (url.includes('/rest/v1/order_lines?order_id=eq.') && init.method === 'DELETE') return new Response(null, { status: 204 });
    if (url.includes('/rest/v1/order_lines') && init.method === 'POST') return new Response(null, { status: 201 });
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/edit-order', {
    method: 'POST', cookie: validCookie,
    body: {
      orderId: '11111111-1111-4111-8111-111111111111',
      passcode: env.EDIT_PASSCODE,
      order: { store_name: 'Shop Marolles' },
      lines: [{ category: 'c', article_fr: 'a', quantity: 1 }],
    },
  }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.ok, true);
  assert.equal(calls.length, 3);
});

console.log('7. POST /api/submit-picking (per-section, no email - September 2026 change)');
await test('single line, that line is the whole order -> fullyPicked true, order PATCHed, NO email/formsubmit call', async () => {
  const calls = [];
  mockFetch(async (url, init) => {
    calls.push({ url, method: init.method });
    if (url.includes('formsubmit.co')) throw new Error('submit-picking must never email directly anymore - that is apiVerifyOrder\'s job');
    if (url.includes('/rest/v1/orders?id=eq.') && !init.method) {
      return new Response(JSON.stringify([{ id: 'oid' }]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?id=eq.') && url.includes('order_id=eq.') && init.method === 'PATCH') {
      const sentBody = JSON.parse(init.body);
      assert.equal(sentBody.picked_by, 'Jean');
      return new Response(JSON.stringify([{}]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?order_id=eq.') && !init.method) {
      // "is everything now picked" re-check
      return new Response(JSON.stringify([{ quantity_picked: 3 }]), { status: 200 });
    }
    if (url.includes('/rest/v1/orders?id=eq.') && init.method === 'PATCH') {
      const sentBody = JSON.parse(init.body);
      assert.ok(sentBody.picking_completed_at, 'expected picking_completed_at to be set once fully picked');
      return new Response('[]', { status: 200 });
    }
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/submit-picking', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', pickedBy: 'Jean', lines: [{ id: '22222222-2222-4222-8222-222222222222', quantity_picked: 3 }] },
  }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.ok, true);
  assert.equal(body.updatedCount, 1);
  assert.equal(body.fullyPicked, true);
  assert.ok(!calls.some(c => c.url.includes('formsubmit.co')));
});

await test('partial submission (other lines of the order still unpicked) -> fullyPicked false, order NOT patched', async () => {
  mockFetch(async (url, init) => {
    if (url.includes('formsubmit.co')) throw new Error('should never email from submit-picking');
    if (url.includes('/rest/v1/orders?id=eq.') && !init.method) {
      return new Response(JSON.stringify([{ id: 'oid' }]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?id=eq.') && url.includes('order_id=eq.') && init.method === 'PATCH') {
      return new Response(JSON.stringify([{}]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?order_id=eq.') && !init.method) {
      // one line from a different section is still null -> not fully picked
      return new Response(JSON.stringify([{ quantity_picked: 3 }, { quantity_picked: null }]), { status: 200 });
    }
    if (url.includes('/rest/v1/orders?id=eq.') && init.method === 'PATCH') {
      throw new Error('orders should not be PATCHed when not fully picked yet');
    }
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/submit-picking', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', pickedBy: 'Birgit', lines: [{ id: '22222222-2222-4222-8222-222222222222', quantity_picked: 3 }] },
  }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.fullyPicked, false);
});

await test('unauthenticated -> 401', async () => {
  const resp = await worker.fetch(req('/api/submit-picking', { method: 'POST', body: { orderId: 'x' } }), env);
  assert.equal(resp.status, 401);
});

console.log('7b. POST /api/verify-order (the only place a discrepancy email is now sent)');
await test('missing verifiedBy -> 400, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const resp = await worker.fetch(req('/api/verify-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111' },
  }), env);
  assert.equal(resp.status, 400);
  const body = await resp.json();
  assert.equal(body.error, 'missing_verified_by');
});

await test('order not found -> 404', async () => {
  mockFetch(async () => new Response(JSON.stringify([]), { status: 200 }));
  const resp = await worker.fetch(req('/api/verify-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', verifiedBy: 'Manu' },
  }), env);
  assert.equal(resp.status, 404);
});

await test('already verified -> 409 already_verified, no lines fetch, no email (idempotency guard)', async () => {
  mockFetch(async (url) => {
    if (url.includes('/rest/v1/orders?id=eq.')) {
      return new Response(JSON.stringify([{ id: 'oid', store_name: 'Shop Marolles', delivery_date: '2026-01-01', verified_at: '2026-09-17T10:00:00.000Z' }]), { status: 200 });
    }
    throw new Error('should stop at the already-verified check, got ' + url);
  });
  const resp = await worker.fetch(req('/api/verify-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', verifiedBy: 'Manu' },
  }), env);
  assert.equal(resp.status, 409);
  const body = await resp.json();
  assert.equal(body.error, 'already_verified');
});

await test('valid, with a diff -> emails shop once, diffCount/emailSent/unpickedCount shape', async () => {
  mockFetch(async (url, init) => {
    if (url.includes('/rest/v1/orders?id=eq.') && !init.method) {
      return new Response(JSON.stringify([{ id: 'oid', store_name: 'Shop Marolles', delivery_date: '2026-01-01', verified_at: null }]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?order_id=eq.')) {
      return new Response(JSON.stringify([
        { quantity: 5, quantity_picked: 3, article_fr: 'Art A', article_nl: '' },   // diff
        { quantity: 2, quantity_picked: 2, article_fr: 'Art B', article_nl: '' },   // no diff
        { quantity: 1, quantity_picked: null, article_fr: 'Art C', article_nl: '' }, // unpicked
      ]), { status: 200 });
    }
    if (url.includes('/rest/v1/orders?id=eq.') && init.method === 'PATCH') {
      const sentBody = JSON.parse(init.body);
      assert.equal(sentBody.verified_by, 'Manu');
      assert.ok(sentBody.verified_at);
      return new Response('[]', { status: 200 });
    }
    if (url.includes('formsubmit.co')) {
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/verify-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', verifiedBy: 'Manu' },
  }), env);
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.ok, true);
  assert.equal(body.diffCount, 1);
  assert.equal(body.emailSent, true);
  assert.equal(body.unpickedCount, 1);
});

await test('valid, no diff among picked lines -> no email sent', async () => {
  mockFetch(async (url, init) => {
    if (url.includes('formsubmit.co')) throw new Error('should not email when there is no discrepancy');
    if (url.includes('/rest/v1/orders?id=eq.') && !init.method) {
      return new Response(JSON.stringify([{ id: 'oid', store_name: 'Shop Marolles', delivery_date: '2026-01-01', verified_at: null }]), { status: 200 });
    }
    if (url.includes('/rest/v1/order_lines?order_id=eq.')) {
      return new Response(JSON.stringify([{ quantity: 2, quantity_picked: 2, article_fr: 'Art', article_nl: '' }]), { status: 200 });
    }
    if (url.includes('/rest/v1/orders?id=eq.') && init.method === 'PATCH') return new Response('[]', { status: 200 });
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/verify-order', {
    method: 'POST', cookie: validCookie,
    body: { orderId: '11111111-1111-4111-8111-111111111111', verifiedBy: 'Manu' },
  }), env);
  const body = await resp.json();
  assert.equal(body.diffCount, 0);
  assert.equal(body.emailSent, false);
});

await test('unauthenticated -> 401', async () => {
  const resp = await worker.fetch(req('/api/verify-order', { method: 'POST', body: { orderId: 'x' } }), env);
  assert.equal(resp.status, 401);
});

console.log('8. Rate limiting (write endpoints)');
await test('WRITE_RATE_LIMITER denies -> 429 rate_limited, supabase never called', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const envWithLimiter = Object.assign({}, env, {
    WRITE_RATE_LIMITER: { limit: async () => ({ success: false }) },
  });
  const resp = await worker.fetch(req('/api/orders', { method: 'POST', cookie: validCookie, body: { order: { store_name: 'x' } } }), envWithLimiter);
  assert.equal(resp.status, 429);
  const body = await resp.json();
  assert.equal(body.error, 'rate_limited');
});

await test('WRITE_RATE_LIMITER absent -> writes still work (graceful skip)', async () => {
  mockFetch(async (url, init) => {
    if (url.includes('/rest/v1/orders') && init.method === 'POST') return new Response(JSON.stringify([{ id: 'x' }]), { status: 201 });
    throw new Error('unexpected ' + url);
  });
  const resp = await worker.fetch(req('/api/orders', { method: 'POST', cookie: validCookie, body: { order: { store_name: 'Shop Marolles' } } }), env);
  assert.equal(resp.status, 200);
});

console.log('9. Missing service role key');
await test('SUPABASE_SERVICE_ROLE_KEY not configured -> 500 server_misconfigured, no supabase call', async () => {
  mockFetch(async () => { throw new Error('should not reach supabase'); });
  const envNoKey = Object.assign({}, env, { SUPABASE_SERVICE_ROLE_KEY: undefined });
  const resp = await worker.fetch(req('/api/orders', { cookie: validCookie }), envNoKey);
  assert.equal(resp.status, 500);
  const body = await resp.json();
  assert.equal(body.error, 'server_misconfigured');
});

console.log('10. Non-api proxy path still works and carries security headers');
await test('authenticated GET / -> proxied, security headers present, no supabase key anywhere', async () => {
  mockFetch(async (url) => {
    assert.ok(url.startsWith('https://oxfam-bon-de-commande.pages.dev'));
    return new Response('<html>hi</html>', { status: 200, headers: { 'Content-Type': 'text/html' } });
  });
  const resp = await worker.fetch(req('/', { cookie: validCookie }), env);
  assert.equal(resp.status, 200);
  // connect-src still allows the Supabase origin (odoo-stock, non-sensitive,
  // read-only) but the page/response must never contain the privileged key.
  assert.equal(resp.headers.get('X-Content-Type-Options'), 'nosniff');
  const text = await resp.text();
  assert.ok(!text.includes(env.SUPABASE_SERVICE_ROLE_KEY));
});

global.fetch = originalFetch;

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
