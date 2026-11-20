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
