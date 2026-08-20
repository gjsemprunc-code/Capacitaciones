-- ============================================================
-- ESQUEMA DE LA PLATAFORMA DE CAPACITACIÓN — VERSIÓN 2
--
-- Reemplaza al archivo original. Se puede ejecutar sobre una base
-- nueva o sobre la que ya tienes: todo está escrito para no fallar
-- si los objetos ya existen.
--
-- Cambios respecto de la versión 1:
--   1. El trigger de dominio ya no intenta borrar filas de
--      auth.users (operación frágil que podía romper el registro).
--      Ahora aborta la transacción, que es la forma correcta.
--   2. Los dos correos administradores quedan definidos y se
--      asignan solos al primer ingreso.
--   3. Se restringen las columnas que un usuario puede escribir en
--      su propio perfil, para que nadie pueda auto-asignarse
--      es_admin desde el navegador.
--
-- Pegar y ejecutar en: Supabase > SQL Editor > New query
-- ============================================================


-- ============================================================
-- 1) TABLAS
-- ============================================================

create table if not exists public.perfiles (
    id uuid primary key references auth.users(id) on delete cascade,
    email text not null,
    nombre_completo text,
    es_admin boolean not null default false,
    ultimo_ingreso timestamptz default now(),
    creado_en timestamptz default now()
);

create table if not exists public.inscripciones (
    id bigserial primary key,
    user_id uuid not null references auth.users(id) on delete cascade,
    curso_id text not null,
    email text not null,
    nombre text,
    rut text,
    iniciado_en timestamptz default now(),
    unique (user_id, curso_id)
);

create table if not exists public.certificados (
    id bigserial primary key,
    user_id uuid not null references auth.users(id) on delete cascade,
    curso_id text not null,
    email text not null,
    nombre text,
    rut text,
    puntaje int,
    aprobado boolean,
    emitido_en timestamptz default now(),
    unique (user_id, curso_id)
);


-- ============================================================
-- 2) VALIDACIÓN DE DOMINIO + ALTA DE PERFIL
--
-- Esta es la barrera real: aunque alguien manipule el JavaScript
-- del navegador, ninguna cuenta fuera del dominio institucional
-- consigue registrarse.
--
-- Para cambiar quiénes son administradores, edita la lista de
-- correos que aparece más abajo (aparece también en el bloque 6).
-- ============================================================

create or replace function public.validar_dominio_institucional()
returns trigger as $$
begin
    if new.email !~* '@minciencia\.gob\.cl$' then
        raise exception 'Dominio no autorizado: %', new.email;
    end if;

    insert into public.perfiles (id, email, nombre_completo, es_admin)
    values (
        new.id,
        new.email,
        coalesce(
            new.raw_user_meta_data->>'full_name',
            new.raw_user_meta_data->>'name',
            ''
        ),
        -- ADMINISTRADORES: se marcan solos al primer ingreso
        lower(new.email) in (
            'gjsemprun.ext@minciencia.gob.cl',
            'kmacginty@minciencia.gob.cl'
        )
    )
    on conflict (id) do nothing;

    return new;
end;
$$ language plpgsql security definer set search_path = public;

drop trigger if exists trigger_validar_dominio on auth.users;
create trigger trigger_validar_dominio
    after insert on auth.users
    for each row execute function public.validar_dominio_institucional();


-- ============================================================
-- 3) ROW LEVEL SECURITY
-- Cada persona solo lee y escribe sus propios datos.
-- ============================================================

alter table public.perfiles enable row level security;
alter table public.inscripciones enable row level security;
alter table public.certificados enable row level security;

drop policy if exists "ver_perfil_propio" on public.perfiles;
create policy "ver_perfil_propio" on public.perfiles for select
    using (auth.uid() = id);

drop policy if exists "actualizar_perfil_propio" on public.perfiles;
create policy "actualizar_perfil_propio" on public.perfiles for update
    using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "insertar_perfil_propio" on public.perfiles;
create policy "insertar_perfil_propio" on public.perfiles for insert
    with check (auth.uid() = id and (auth.jwt() ->> 'email') ~* '@minciencia\.gob\.cl$');

drop policy if exists "ver_inscripcion_propia" on public.inscripciones;
create policy "ver_inscripcion_propia" on public.inscripciones for select
    using (auth.uid() = user_id);

drop policy if exists "crear_inscripcion_propia" on public.inscripciones;
create policy "crear_inscripcion_propia" on public.inscripciones for insert
    with check (auth.uid() = user_id and (auth.jwt() ->> 'email') ~* '@minciencia\.gob\.cl$');

drop policy if exists "actualizar_inscripcion_propia" on public.inscripciones;
create policy "actualizar_inscripcion_propia" on public.inscripciones for update
    using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "ver_certificado_propio" on public.certificados;
create policy "ver_certificado_propio" on public.certificados for select
    using (auth.uid() = user_id);

drop policy if exists "crear_certificado_propio" on public.certificados;
create policy "crear_certificado_propio" on public.certificados for insert
    with check (auth.uid() = user_id and (auth.jwt() ->> 'email') ~* '@minciencia\.gob\.cl$');

drop policy if exists "actualizar_certificado_propio" on public.certificados;
create policy "actualizar_certificado_propio" on public.certificados for update
    using (auth.uid() = user_id) with check (auth.uid() = user_id);


-- ============================================================
-- 4) PANEL DE ADMINISTRADOR
-- Permite a quien tenga es_admin = true ver TODAS las filas.
-- ============================================================

create or replace function public.es_administrador()
returns boolean as $$
    select coalesce(
        (select es_admin from public.perfiles where id = auth.uid()),
        false
    );
$$ language sql security definer stable set search_path = public;

drop policy if exists "admin_ve_todos_los_perfiles" on public.perfiles;
create policy "admin_ve_todos_los_perfiles" on public.perfiles for select
    using (public.es_administrador());

drop policy if exists "admin_ve_todas_las_inscripciones" on public.inscripciones;
create policy "admin_ve_todas_las_inscripciones" on public.inscripciones for select
    using (public.es_administrador());

drop policy if exists "admin_ve_todos_los_certificados" on public.certificados;
create policy "admin_ve_todos_los_certificados" on public.certificados for select
    using (public.es_administrador());


-- ============================================================
-- 5) BLINDAJE DE LA COLUMNA es_admin
--
-- Sin esto, cualquier funcionario podría abrir la consola del
-- navegador y escribir es_admin = true en su propia fila: la
-- política de RLS autoriza modificar el registro propio, pero no
-- distingue entre columnas. Aquí se limita a nivel de permisos.
--
-- La aplicación sigue funcionando igual, porque solo escribe las
-- columnas que quedan autorizadas.
-- ============================================================

revoke insert, update on public.perfiles from authenticated;

grant insert (id, email, nombre_completo, ultimo_ingreso)
    on public.perfiles to authenticated;

grant update (nombre_completo, ultimo_ingreso)
    on public.perfiles to authenticated;


-- ============================================================
-- 6) ASIGNAR LOS ADMINISTRADORES ACTUALES
--
-- Marca a quienes ya iniciaron sesión alguna vez. Pone es_admin
-- en false a cualquier otra cuenta, así que también sirve para
-- revocar permisos.
-- ============================================================

update public.perfiles
set es_admin = lower(email) in (
    'gjsemprun.ext@minciencia.gob.cl',
    'kmacginty@minciencia.gob.cl'
);


-- ============================================================
-- 7) VERIFICACIÓN
-- Ejecuta esto para confirmar quién quedó con acceso al panel.
-- ============================================================

select email, es_admin, creado_en
from public.perfiles
order by es_admin desc, creado_en desc;
