-- Recreate `org_invites` empty. This down-migration is intentionally lossy:
-- pending invites migrated up became `identities` rows and are NOT round-tripped
-- back (the identities survive and keep working as pre-created members). The
-- table is restored only so a rollback lands on a schema the older code expects.

CREATE TABLE public.org_invites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    email text NOT NULL,
    role text NOT NULL,
    invited_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_at timestamp with time zone,
    accepted_by_user_id uuid,
    CONSTRAINT org_invites_email_lower CHECK ((email = lower(email))),
    CONSTRAINT org_invites_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'member'::text])))
);

ALTER TABLE ONLY public.org_invites
    ADD CONSTRAINT org_invites_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_invites
    ADD CONSTRAINT org_invites_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_invites
    ADD CONSTRAINT org_invites_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.identities(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.org_invites
    ADD CONSTRAINT org_invites_accepted_by_user_id_fkey FOREIGN KEY (accepted_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

CREATE INDEX org_invites_by_org_email ON public.org_invites USING btree (org_id, email);

CREATE UNIQUE INDEX org_invites_one_pending_per_email ON public.org_invites USING btree (org_id, email) WHERE (accepted_at IS NULL);
