-- Supabase RLS/grant lockdown for orders + order_lines.
--
-- RUN THIS ONLY AFTER:
--   1. The new Cloudflare Worker (with /api/orders, /api/orders/:id,
--      /api/order-lines, /api/edit-order, /api/submit-picking) is deployed
--      and SUPABASE_SERVICE_ROLE_KEY + EDIT_PASSCODE secrets are set.
--   2. index.html, dashboard.html and picking.html have been redeployed to
--      point at those /api/* routes instead of Supabase directly.
--   3. You have manually verified, through the real app (logged in):
--        - submitting a new order works
--        - the dashboard loads and shows existing orders
--        - editing an existing order works
--        - the picking page loads an order and "Valider la préparation" works
--   4. All the above still work RIGHT NOW, before running this file - the
--      Worker uses the service_role key and therefore does not depend on
--      anon's RLS/grants at all, so testing step 3 is safe to do before
--      running this script.
--
-- What this does: removes the public.orders / public.order_lines access
-- that the anon (public, embedded-in-the-browser) key currently has. After
-- this runs, the anon key + project URL alone can no longer read, insert,
-- update, or delete anything in either table - every app feature must go
-- through the Worker's service_role-backed /api/* routes.
--
-- This does NOT touch service_role's grants (unchanged, already correct)
-- and does NOT disable Row Level Security on either table.

begin;

-- 1) Drop the four "wide open to anon" policies.
drop policy if exists "public select orders" on public.orders;
drop policy if exists "public insert orders" on public.orders;
drop policy if exists "public select order_lines" on public.order_lines;
drop policy if exists "public insert order_lines" on public.order_lines;

-- 2) Belt-and-suspenders: revoke the table-level grants Supabase gives
--    `anon` by default, on top of dropping the policies above. With RLS
--    enabled and zero policies for anon, PostgREST would already deny anon
--    every operation - this makes it deny at the permission level too, so
--    a future accidental "create policy ... to anon using (true)" alone
--    wouldn't be enough to reopen access without also re-granting here.
revoke all on public.orders from anon;
revoke all on public.order_lines from anon;

commit;

-- After running this, verify (see the negative-test list in the summary
-- message) that:
--   curl "$SUPABASE_URL/rest/v1/orders?select=*" -H "apikey: $ANON_KEY"
-- returns an empty/permission-denied response, not order data.
