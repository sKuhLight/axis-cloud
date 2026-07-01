-- Anonymous, insert-only debug-report bucket used by ForgeFX telemetry (uploadDebugReport).
-- Reports are keyed by an anonymous instance id, not an account, so there is NO auth on insert; but there
-- is no SELECT/UPDATE/DELETE policy, so a client can push a report yet never list, read, or delete any —
-- including its own. Bundles are brotli-compressed JSON, capped at 5 MiB.
insert into storage.buckets (id, name, public, file_size_limit)
values ('debug-reports', 'debug-reports', false, 5242880)
on conflict (id) do nothing;

create policy "debug_reports_insert" on storage.objects
  for insert to anon, authenticated
  with check (bucket_id = 'debug-reports');
