-- Leaderboard (run after schema.sql). Points = correct answers.
-- The browser reports its own answer counts, so the server only lets points grow at human speed:
-- at most 1 point per second since the last save, and at most 1,200 points per day.
-- A faked report can never jump to the top; the most anyone can gain is a busy human day.

alter table public.accounts add column if not exists on_board boolean not null default true;
alter table public.stats add column if not exists points int not null default 0;
alter table public.stats add column if not exists ans int not null default 0;
alter table public.stats add column if not exists wrong int not null default 0;
alter table public.stats add column if not exists day date not null default current_date;
alter table public.stats add column if not exists today int not null default 0;

-- Usernames are shown to everyone now: no invisible or text-direction characters (they can disguise a name).
do $$ begin
  alter table public.accounts add constraint bad_username
    check (username !~ '[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]');
exception when duplicate_object then null; end $$;

-- Total answers and wrong answers a stats object claims (each checklist capped, junk ignored).
create or replace function public._claim(p jsonb, out n bigint, out w bigint)
language sql immutable set search_path = public as $$
  select coalesce(sum(least(greatest((e.value->>'n')::numeric, 0), 100000)), 0)::bigint,
         coalesce(sum(least(greatest((e.value->>'w')::numeric, 0), 100000)), 0)::bigint
    from jsonb_each(case when jsonb_typeof(p) = 'object' then p else '{}'::jsonb end) e
   where jsonb_typeof(e.value) = 'object'
     and jsonb_typeof(e.value->'n') = 'number' and jsonb_typeof(e.value->'w') = 'number'
$$;

create or replace function public.save_progress(p_token text, p_state jsonb, p_stats jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid := _session(p_token); r stats%rowtype; c record; v_since timestamptz; v_today int; v_gain bigint;
begin
  if v_id is null then raise exception 'no_session'; end if;
  if jsonb_typeof(p_state) <> 'object' or octet_length(p_state::text) > 2000000 then raise exception 'bad_state'; end if;
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

-- Top 10 (only people who didn't hide themselves) and, with a token, the caller's own rank.
create or replace function public.leaderboard(p_token text default null) returns json
language sql stable security definer set search_path = public as $$
  with b as (
    select a.id, a.username, s.points, s.ans, s.wrong, rank() over (order by s.points desc) as rk
      from stats s join accounts a on a.id = s.account
     where s.points > 0 and a.on_board
  ), me as (select _session(p_token) as id)
  select json_build_object(
    'top', (select coalesce(json_agg(json_build_object('u', username, 'p', points, 'r', rk,
                      'a', case when ans >= 20 then round(100.0 * greatest(ans - wrong, 0) / ans) end) order by rk, username), '[]'::json)
              from (select * from b order by rk, username limit 10) t),
    'me', (select json_build_object('r', (select rk from b where b.id = a.id), 'p', coalesce(s.points, 0), 'on', a.on_board)
             from me join accounts a on a.id = me.id left join stats s on s.account = a.id))
$$;

create or replace function public.set_board(p_token text, p_on boolean) returns json
language plpgsql security definer set search_path = public as $$
declare v_id uuid := _session(p_token);
begin
  if v_id is null then raise exception 'no_session'; end if;
  update accounts set on_board = coalesce(p_on, true) where id = v_id;
  return json_build_object('ok', true);
end $$;

-- Existing accounts start from what they already have (one time, below the daily cap).
update public.stats s set points = least(greatest(c.n - c.w, 0), 1200), ans = c.n, wrong = c.w
  from (select account, (public._claim(data)).* from public.stats) c
 where c.account = s.account and s.points = 0;

revoke execute on function public._claim(jsonb) from public, anon, authenticated;
grant execute on function public.leaderboard(text), public.set_board(text, boolean) to anon, authenticated;

-- sign_up checks the name itself, so a rejected name never echoes the row back in an error.
create or replace function public.sign_up(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_name text := btrim(coalesce(p_username, '')); v_id uuid;
begin
  if char_length(v_name) not between 2 and 24 or v_name ~ '[[:cntrl:]]'
     or v_name ~ '[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]' then raise exception 'bad_username'; end if;
  if char_length(coalesce(p_password, '')) < 6 or char_length(p_password) > 200 then raise exception 'weak_password'; end if;
  delete from signup_log where at < now() - interval '1 day';
  if (select count(*) from signup_log where at > now() - interval '10 minutes') >= 20 then raise exception 'busy'; end if;
  begin
    insert into accounts(username, pw) values (v_name, crypt(p_password, gen_salt('bf', 10))) returning id into v_id;
  exception when unique_violation then
    raise exception 'username_taken';
  end;
  insert into signup_log default values;
  return json_build_object('token', _new_session(v_id), 'username', v_name);
end $$;
