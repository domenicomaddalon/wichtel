create extension if not exists pgcrypto;
create table if not exists public.wichtel_rounds(id uuid primary key default gen_random_uuid(),admin_id uuid not null references auth.users(id),title text not null,notes text not null default '',created_at timestamptz not null default now());
create table if not exists public.wichtel_participants(id uuid primary key default gen_random_uuid(),round_id uuid not null references public.wichtel_rounds(id) on delete cascade,name text not null,email text not null,unique(round_id,email),unique(id,round_id));
create table if not exists public.wichtel_exclusions(id uuid primary key default gen_random_uuid(),round_id uuid not null references public.wichtel_rounds(id) on delete cascade,person_a uuid not null,person_b uuid not null,foreign key(person_a,round_id) references public.wichtel_participants(id,round_id) on delete cascade,foreign key(person_b,round_id) references public.wichtel_participants(id,round_id) on delete cascade,check(person_a < person_b),unique(round_id,person_a,person_b));
create table if not exists public.wichtel_assignments(round_id uuid not null references public.wichtel_rounds(id) on delete cascade,giver_id uuid not null,receiver_id uuid not null,token_hash text not null unique,token text not null unique,primary key(round_id,giver_id),unique(round_id,receiver_id),foreign key(giver_id,round_id) references public.wichtel_participants(id,round_id),foreign key(receiver_id,round_id) references public.wichtel_participants(id,round_id),check(giver_id<>receiver_id));
create index if not exists wichtel_assignments_token_hash_idx on public.wichtel_assignments(token_hash);
alter table public.wichtel_rounds enable row level security;
alter table public.wichtel_participants enable row level security;
alter table public.wichtel_exclusions enable row level security;
alter table public.wichtel_assignments enable row level security;
revoke all on public.wichtel_assignments from anon,authenticated;
grant select,insert,update,delete on public.wichtel_rounds,public.wichtel_participants,public.wichtel_exclusions to authenticated;
create policy "round owner" on public.wichtel_rounds for all to authenticated using(admin_id=(select auth.uid())) with check(admin_id=(select auth.uid()));
create policy "participant owner" on public.wichtel_participants for all to authenticated using(exists(select 1 from public.wichtel_rounds r where r.id=round_id and r.admin_id=(select auth.uid()))) with check(exists(select 1 from public.wichtel_rounds r where r.id=round_id and r.admin_id=(select auth.uid())));
create policy "exclusion owner" on public.wichtel_exclusions for all to authenticated using(exists(select 1 from public.wichtel_rounds r where r.id=round_id and r.admin_id=(select auth.uid()))) with check(exists(select 1 from public.wichtel_rounds r where r.id=round_id and r.admin_id=(select auth.uid())));
create or replace function public.wichtel_assert_editable(p_round uuid) returns trigger language plpgsql security definer set search_path='' as $$begin if exists(select 1 from public.wichtel_assignments where round_id=(case when tg_op = 'DELETE' then old.round_id else new.round_id end)) then raise exception 'Runde bereits ausgelost: Änderungen gesperrt';end if;if tg_op = 'DELETE' then return old; else return new; end if;end$$;
create trigger wichtel_participants_lock before insert or update or delete on public.wichtel_participants for each row execute function public.wichtel_assert_editable();
create trigger wichtel_exclusions_lock before insert or update or delete on public.wichtel_exclusions for each row execute function public.wichtel_assert_editable();
create or replace function public.wichtel_round_status(p_round uuid) returns jsonb language plpgsql security definer set search_path='' as $$begin if not exists(select 1 from public.wichtel_rounds where id=p_round and admin_id=auth.uid()) then raise exception 'Keine Berechtigung';end if;return jsonb_build_object('drawn',exists(select 1 from public.wichtel_assignments where round_id=p_round));end$$;
create or replace function public.wichtel_draw(p_round uuid) returns integer language plpgsql security definer set search_path='' as $$declare ids uuid[]; shuffled uuid[]; n integer; i integer; attempts integer; ok boolean; t text;begin
if not exists(select 1 from public.wichtel_rounds where id=p_round and admin_id=auth.uid()) then raise exception 'Keine Berechtigung';end if;
perform pg_advisory_xact_lock(hashtext(p_round::text));
if exists(select 1 from public.wichtel_assignments where round_id=p_round) then raise exception 'Bereits ausgelost';end if;
select array_agg(id order by id) into ids from public.wichtel_participants where round_id=p_round;
n:=coalesce(array_length(ids,1),0);if n<2 then raise exception 'Mindestens zwei Teilnehmer erforderlich';end if;
for attempts in 1..20000 loop
 select array_agg(x order by random()) into shuffled from unnest(ids) x;
 ok:=true;
 for i in 1..n loop
 if ids[i]=shuffled[i] or exists(select 1 from public.wichtel_exclusions e where e.round_id=p_round and ((e.person_a=least(ids[i],shuffled[i]) and e.person_b=greatest(ids[i],shuffled[i])))) then ok:=false;exit;end if;
 end loop;
 if ok then exit;end if;
end loop;
if not ok then raise exception 'Keine gültige Auslosung gefunden. Ausschlussregeln prüfen.';end if;
for i in 1..n loop
 t:=encode(gen_random_bytes(32),'hex');
 insert into public.wichtel_assignments(round_id,giver_id,receiver_id,token,token_hash) values(p_round,ids[i],shuffled[i],t,encode(digest(t,'sha256'),'hex'));
end loop;
return n;end$$;
create or replace function public.wichtel_invites(p_round uuid) returns table(name text,email text,token text) language plpgsql security definer set search_path='' as $$begin if not exists(select 1 from public.wichtel_rounds r where r.id=p_round and r.admin_id=auth.uid()) then raise exception 'Keine Berechtigung';end if;return query select p.name,p.email,a.token from public.wichtel_assignments a join public.wichtel_participants p on p.id=a.giver_id where a.round_id=p_round order by p.name;end$$;
create or replace function public.wichtel_reveal(p_token text) returns text language plpgsql security definer set search_path='' as $$declare result text;begin if length(p_token)<>64 or p_token !~ '^[0-9a-f]+$' then return null;end if;select p.name into result from public.wichtel_assignments a join public.wichtel_participants p on p.id=a.receiver_id where a.token_hash=encode(digest(p_token,'sha256'),'hex');return result;end$$;
revoke all on function public.wichtel_assert_editable(uuid) from public,anon,authenticated;
revoke all on function public.wichtel_round_status(uuid),public.wichtel_draw(uuid),public.wichtel_invites(uuid),public.wichtel_reveal(text) from public;
grant execute on function public.wichtel_round_status(uuid),public.wichtel_draw(uuid),public.wichtel_invites(uuid) to authenticated;
grant execute on function public.wichtel_reveal(text) to anon,authenticated;