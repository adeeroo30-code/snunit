-- Snunit study app: usernames/passwords, saved progress, and everyone's "hardest checklist" stats.
-- Run once in Supabase: Dashboard -> SQL Editor -> New query -> paste -> Run.
-- The browser never touches the tables directly; it only calls the functions below.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.accounts (
  id         uuid primary key default gen_random_uuid(),
  username   text not null check (char_length(username) between 2 and 24),
  pw         text not null,                       -- bcrypt hash, never the password
  created_at timestamptz not null default now()
);
create unique index if not exists accounts_username_lower on public.accounts (lower(username));

create table if not exists public.sessions (
  token      text primary key,
  account    uuid not null references public.accounts on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.progress (
  account    uuid primary key references public.accounts on delete cascade,
  state      jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.stats (
  account    uuid primary key references public.accounts on delete cascade,
  data       jsonb not null,                      -- {checklistId: {n, w, it: {stepIndex: wrong}}}
  updated_at timestamptz not null default now()
);

-- Lock the tables: RLS on with no policies, and no table rights for the public API roles.
alter table public.accounts enable row level security;
alter table public.sessions enable row level security;
alter table public.progress enable row level security;
alter table public.stats    enable row level security;
revoke all on public.accounts, public.sessions, public.progress, public.stats from anon, authenticated;

create or replace function public._session(p_token text) returns uuid
language sql stable security definer set search_path = public as $$
  select account from sessions where token = p_token and created_at > now() - interval '180 days'
$$;

create or replace function public._new_session(p_account uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare v_token text := encode(gen_random_bytes(32), 'hex');
begin
  delete from sessions where account = p_account and created_at < now() - interval '180 days';
  insert into sessions(token, account) values (v_token, p_account);
  return v_token;
end $$;

create or replace function public.sign_up(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_name text := btrim(coalesce(p_username, '')); v_id uuid;
begin
  if char_length(v_name) not between 2 and 24 or v_name ~ '[[:cntrl:]]' then raise exception 'bad_username'; end if;
  if char_length(coalesce(p_password, '')) < 6 or char_length(p_password) > 200 then raise exception 'weak_password'; end if;
  begin
    insert into accounts(username, pw) values (v_name, crypt(p_password, gen_salt('bf', 10))) returning id into v_id;
  exception when unique_violation then
    raise exception 'username_taken';
  end;
  return json_build_object('token', _new_session(v_id), 'username', v_name);
end $$;

create or replace function public.sign_in(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_name text;
begin
  select id, username into v_id, v_name from accounts
   where lower(username) = lower(btrim(coalesce(p_username, ''))) and pw = crypt(coalesce(p_password, ''), pw);
  if v_id is null then
    perform pg_sleep(0.5);                         -- slow down password guessing
    raise exception 'bad_login';
  end if;
  return json_build_object('token', _new_session(v_id), 'username', v_name);
end $$;

create or replace function public.sign_out(p_token text) returns void
language sql security definer set search_path = public as $$
  delete from sessions where token = p_token
$$;

create or replace function public.load_progress(p_token text) returns json
language plpgsql stable security definer set search_path = public as $$
declare v_id uuid := _session(p_token);
begin
  if v_id is null then raise exception 'no_session'; end if;
  return (select json_build_object('username', a.username, 'state', p.state)
            from accounts a left join progress p on p.account = a.id where a.id = v_id);
end $$;

create or replace function public.save_progress(p_token text, p_state jsonb, p_stats jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid := _session(p_token);
begin
  if v_id is null then raise exception 'no_session'; end if;
  if jsonb_typeof(p_state) <> 'object' or octet_length(p_state::text) > 2000000 then raise exception 'bad_state'; end if;
  insert into progress(account, state, updated_at) values (v_id, p_state, now())
    on conflict (account) do update set state = excluded.state, updated_at = now();
  if jsonb_typeof(p_stats) = 'object' and octet_length(p_stats::text) < 300000 then
    insert into stats(account, data, updated_at) values (v_id, p_stats, now())
      on conflict (account) do update set data = excluded.data, updated_at = now();
  end if;
end $$;

-- Anonymous totals for the home screen: error rate per checklist and the most-missed steps.
create or replace function public.hardest() returns json
language sql stable security definer set search_path = public as $$
  with c as (
    select s.account, e.key as cl, e.value as v
      from stats s, jsonb_each(s.data) e
     where jsonb_typeof(e.value) = 'object'
  ), cls as (
    select cl,
           sum(case when jsonb_typeof(v->'n') = 'number' then least(greatest((v->>'n')::numeric, 0), 100000) else 0 end) as n,
           sum(case when jsonb_typeof(v->'w') = 'number' then least(greatest((v->>'w')::numeric, 0), 100000) else 0 end) as w,
           count(distinct account) as u
      from c group by cl
  ), its as (
    select c.cl, i.key as it,
           sum(least(greatest((i.value #>> '{}')::numeric, 0), 10000)) as w,
           count(distinct c.account) as u
      from c, jsonb_each(case when jsonb_typeof(c.v->'it') = 'object' then c.v->'it' else '{}'::jsonb end) i
     where jsonb_typeof(i.value) = 'number'
     group by c.cl, i.key
  )
  select json_build_object(
    'cls',   (select coalesce(json_agg(cls), '[]'::json) from cls),
    'items', (select coalesce(json_agg(t), '[]'::json) from (select * from its order by w desc limit 20) t),
    'users', (select count(*) from accounts))
$$;

-- Only the public functions are callable from the browser.
revoke execute on function public._session(text), public._new_session(uuid) from public, anon, authenticated;
grant execute on function public.sign_up(text, text), public.sign_in(text, text), public.sign_out(text),
  public.load_progress(text), public.save_progress(text, jsonb, jsonb), public.hardest() to anon, authenticated;

-- Security update (run after schema.sql): login lockout, sign-up throttle, self-service account deletion.

create table if not exists public.login_fail (name text primary key, n int not null default 0, last timestamptz not null default now());
create table if not exists public.signup_log (at timestamptz not null default now());
alter table public.login_fail enable row level security;
alter table public.signup_log enable row level security;
revoke all on public.login_fail, public.signup_log from anon, authenticated;

-- sign_in returns {error} instead of raising, so the failed-attempt counter is kept (a raise would roll it back).
create or replace function public.sign_in(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_key text := lower(btrim(coalesce(p_username, ''))); v_id uuid; v_name text; v_n int; v_last timestamptz;
begin
  select n, last into v_n, v_last from login_fail where name = v_key;
  if v_n >= 5 and v_last > now() - interval '15 minutes' then return json_build_object('error', 'locked'); end if;
  select id, username into v_id, v_name from accounts
   where lower(username) = v_key and pw = crypt(coalesce(p_password, ''), pw);
  if v_id is null then
    insert into login_fail(name, n, last) values (v_key, 1, now())
      on conflict (name) do update set n = case when login_fail.last < now() - interval '15 minutes' then 1 else login_fail.n + 1 end, last = now();
    return json_build_object('error', 'bad_login');
  end if;
  delete from login_fail where name = v_key;
  return json_build_object('token', _new_session(v_id), 'username', v_name);
end $$;

create or replace function public.sign_up(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_name text := btrim(coalesce(p_username, '')); v_id uuid;
begin
  if char_length(v_name) not between 2 and 24 or v_name ~ '[[:cntrl:]]' then raise exception 'bad_username'; end if;
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

-- Deletes the account and everything stored for it (progress, stats, sessions). Needs the password again.
create or replace function public.delete_account(p_token text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid := _session(p_token);
begin
  if v_id is null then raise exception 'no_session'; end if;
  if not exists (select 1 from accounts where id = v_id and pw = crypt(coalesce(p_password, ''), pw)) then
    return json_build_object('error', 'bad_login');
  end if;
  delete from accounts where id = v_id;
  return json_build_object('ok', true);
end $$;

grant execute on function public.sign_in(text, text), public.sign_up(text, text), public.delete_account(text, text) to anon, authenticated;
