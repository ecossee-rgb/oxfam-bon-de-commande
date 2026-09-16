-- Emergency rollback for supabase-lockdown.sql.
--
-- Only run this if, after locking down anon access, something in the app
-- breaks in a way you need to undo immediately while you investigate (it
-- should NOT be needed if the Worker was tested per supabase-lockdown.sql's
-- checklist before that script ran). This restores exactly the RLS
-- policies and grants that existed before the lockdown - i.e. it goes back
-- to the anon key being able to freely SELECT and INSERT on both tables,
-- which is the state this whole migration was meant to fix. Treat this as
-- a temporary "stop the bleeding" step, not a real fix - re-apply the
-- lockdown once the underlying issue is resolved.

begin;

grant delete, insert, references, select, trigger, truncate, update
  on public.orders to anon;
grant delete, insert, references, select, trigger, truncate, update
  on public.order_lines to anon;

create policy "public select orders"
  on public.orders
  as permissive
  for select
  to anon
  using (true);

create policy "public insert orders"
  on public.orders
  as permissive
  for insert
  to anon
  with check (true);

create policy "public select order_lines"
  on public.order_lines
  as permissive
  for select
  to anon
  using (true);

create policy "public insert order_lines"
  on public.order_lines
  as permissive
  for insert
  to anon
  with check (true);

commit;
