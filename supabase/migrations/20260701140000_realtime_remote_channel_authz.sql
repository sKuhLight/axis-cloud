-- Axis Cloud Remote: private Realtime channel authorization.
-- A user may receive (SELECT) and send (INSERT) ONLY on their own channel `remote:<their-uid>`.
-- Any other topic has no matching policy → denied, so cross-user access is impossible by construction.
-- Both legs — the PC host and the remote browser — are the SAME authenticated user, so they share the
-- one channel and nobody else can ever join it.
create policy "axis remote channel: receive own"
  on realtime.messages for select to authenticated
  using ( realtime.topic() = 'remote:' || (select auth.uid())::text );

create policy "axis remote channel: send own"
  on realtime.messages for insert to authenticated
  with check ( realtime.topic() = 'remote:' || (select auth.uid())::text );
