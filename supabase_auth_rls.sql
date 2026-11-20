alter table public.audit_reports add column if not exists user_id uuid references auth.users(id) default auth.uid();
alter table public.audit_reports enable row level security;

drop policy if exists "audit_reports_select_own" on public.audit_reports;
drop policy if exists "audit_reports_insert_own" on public.audit_reports;
drop policy if exists "audit_reports_delete_own" on public.audit_reports;

create policy "audit_reports_select_own" on public.audit_reports
  for select using (auth.uid() = user_id);

create policy "audit_reports_insert_own" on public.audit_reports
  for insert with check (auth.uid() = user_id);

create policy "audit_reports_delete_own" on public.audit_reports
  for delete using (auth.uid() = user_id);
