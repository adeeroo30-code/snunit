-- 2026-11-20: switch to the June 2025 booklet and the new area map. Everyone restarts from zero; accounts stay.
-- Old progress and stats are kept in locked backup tables (no API access) in case they are ever needed.
create table if not exists public.backup_20261120_progress as table public.progress;
create table if not exists public.backup_20261120_stats as table public.stats;
alter table public.backup_20261120_progress enable row level security;
alter table public.backup_20261120_stats enable row level security;
revoke all on public.backup_20261120_progress, public.backup_20261120_stats from anon, authenticated;

delete from public.progress;
delete from public.stats;     -- also clears leaderboard points and the shared "hardest" numbers

create or replace function public.save_progress(p_token text, p_state jsonb, p_stats jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid := _session(p_token); r stats%rowtype; c record; v_since timestamptz; v_today int; v_gain bigint;
begin
  if v_id is null then raise exception 'no_session'; end if;
  if jsonb_typeof(p_state) <> 'object' or octet_length(p_state::text) > 2000000 then raise exception 'bad_state'; end if;
  -- States from the old app (before the June 2025 booklet) are refused, so an open old tab can't bring old progress back.
  if (case when jsonb_typeof(p_state->'ver') = 'number' then (p_state->>'ver')::numeric else 0 end) < 2 then raise exception 'old_app'; end if;
  insert into progress(account, state, updated_at) values (v_id, p_state, now())
    on conflict (account) do update set state = excluded.state, updated_at = now();
  if jsonb_typeof(p_stats) = 'object' and octet_length(p_stats::text) < 300000 then
    select * into r from stats where account = v_id for update;
    select * into c from _claim(p_stats);
    v_since := coalesce(r.updated_at, (select created_at from accounts where id = v_id));
    v_today := case when r.day = current_date then r.today else 0 end;
    v_gain := greatest(0, least(greatest(c.n - c.w, 0) - coalesce(r.points, 0),
                                floor(extract(epoch from now() - v_since))::bigint,
                                1200 - v_today));
    insert into stats(account, data, updated_at, points, ans, wrong, day, today)
      values (v_id, p_stats, now(), v_gain, c.n, c.w, current_date, v_gain)
      on conflict (account) do update set data = excluded.data, updated_at = now(), points = stats.points + v_gain,
        ans = excluded.ans, wrong = excluded.wrong, day = current_date, today = v_today + v_gain;
  end if;
end $$;
