--
-- PostgreSQL database dump
--

\restrict YJ2nPdNQU3lkbTpvJENgOzIz7JgnAmgbztuagCojNYBowFARNyGwx2ZkDgf0s1v

-- Dumped from database version 16.13
-- Dumped by pg_dump version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid,
    name text NOT NULL,
    key_hash text NOT NULL,
    key_prefix text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approvals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    action_summary text NOT NULL,
    action_detail jsonb,
    permission_keys text[] DEFAULT '{}'::text[] NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by text,
    remember boolean DEFAULT false NOT NULL,
    token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'allowed'::text, 'denied'::text, 'expired'::text])))
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid,
    action text NOT NULL,
    resource_type text,
    resource_id uuid,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_address text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: byoc_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.byoc_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid,
    provider_key text NOT NULL,
    encrypted_client_id bytea NOT NULL,
    encrypted_client_secret bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    provider_key text NOT NULL,
    encrypted_access_token bytea NOT NULL,
    encrypted_refresh_token bytea,
    token_expires_at timestamp with time zone,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    account_email text,
    byoc_credential_id uuid,
    is_default boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    external_id text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identities_kind_check CHECK ((kind = ANY (ARRAY['user'::text, 'agent'::text])))
);


--
-- Name: oauth_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_providers (
    key text NOT NULL,
    display_name text NOT NULL,
    authorization_endpoint text NOT NULL,
    token_endpoint text NOT NULL,
    revocation_endpoint text,
    userinfo_endpoint text,
    client_id_pattern text,
    supports_pkce boolean DEFAULT false NOT NULL,
    supports_refresh boolean DEFAULT true NOT NULL,
    extra_auth_params jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_builtin boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: orgs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orgs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: permission_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permission_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    action_pattern text NOT NULL,
    effect text DEFAULT 'allow'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT permission_rules_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text])))
);


--
-- Name: secret_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    secret_id uuid NOT NULL,
    version integer NOT NULL,
    encrypted_value bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    current_version integer DEFAULT 1 NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    subscription_id uuid NOT NULL,
    event text NOT NULL,
    payload jsonb NOT NULL,
    status_code integer,
    response_body text,
    attempts integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp with time zone,
    delivered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: webhook_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    url text NOT NULL,
    events text[] NOT NULL,
    secret text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: approvals approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (id);


--
-- Name: approvals approvals_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_token_key UNIQUE (token);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: byoc_credentials byoc_credentials_org_id_identity_id_provider_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.byoc_credentials
    ADD CONSTRAINT byoc_credentials_org_id_identity_id_provider_key_key UNIQUE (org_id, identity_id, provider_key);


--
-- Name: byoc_credentials byoc_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.byoc_credentials
    ADD CONSTRAINT byoc_credentials_pkey PRIMARY KEY (id);


--
-- Name: connections connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);


--
-- Name: identities identities_org_id_external_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_org_id_external_id_key UNIQUE (org_id, external_id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: oauth_providers oauth_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_providers
    ADD CONSTRAINT oauth_providers_pkey PRIMARY KEY (key);


--
-- Name: orgs orgs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orgs
    ADD CONSTRAINT orgs_pkey PRIMARY KEY (id);


--
-- Name: orgs orgs_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orgs
    ADD CONSTRAINT orgs_slug_key UNIQUE (slug);


--
-- Name: permission_rules permission_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission_rules
    ADD CONSTRAINT permission_rules_pkey PRIMARY KEY (id);


--
-- Name: secret_versions secret_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_pkey PRIMARY KEY (id);


--
-- Name: secret_versions secret_versions_secret_id_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_secret_id_version_key UNIQUE (secret_id, version);


--
-- Name: secrets secrets_org_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_org_id_name_key UNIQUE (org_id, name);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_subscriptions webhook_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: idx_api_keys_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_org ON public.api_keys USING btree (org_id);


--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);


--
-- Name: idx_approvals_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_expires ON public.approvals USING btree (expires_at) WHERE (status = 'pending'::text);


--
-- Name: idx_approvals_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_identity ON public.approvals USING btree (identity_id);


--
-- Name: idx_approvals_org_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_org_status ON public.approvals USING btree (org_id, status);


--
-- Name: idx_audit_log_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_identity ON public.audit_log USING btree (identity_id, created_at DESC);


--
-- Name: idx_audit_log_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_org ON public.audit_log USING btree (org_id, created_at DESC);


--
-- Name: idx_connections_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_identity ON public.connections USING btree (identity_id);


--
-- Name: idx_connections_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_provider ON public.connections USING btree (org_id, provider_key);


--
-- Name: idx_identities_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_org ON public.identities USING btree (org_id);


--
-- Name: idx_permission_rules_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_permission_rules_identity ON public.permission_rules USING btree (identity_id);


--
-- Name: byoc_credentials_org_provider_null_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX byoc_credentials_org_provider_null_identity ON public.byoc_credentials USING btree (org_id, provider_key) WHERE (identity_id IS NULL);


--
-- Name: idx_secret_versions_secret; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_secret ON public.secret_versions USING btree (secret_id);


--
-- Name: idx_webhook_deliveries_retry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_deliveries_retry ON public.webhook_deliveries USING btree (next_retry_at) WHERE ((delivered_at IS NULL) AND (attempts < 5));


--
-- Name: api_keys api_keys_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: approvals approvals_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: approvals approvals_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: audit_log audit_log_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: byoc_credentials byoc_credentials_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.byoc_credentials
    ADD CONSTRAINT byoc_credentials_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: byoc_credentials byoc_credentials_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.byoc_credentials
    ADD CONSTRAINT byoc_credentials_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: byoc_credentials byoc_credentials_provider_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.byoc_credentials
    ADD CONSTRAINT byoc_credentials_provider_key_fkey FOREIGN KEY (provider_key) REFERENCES public.oauth_providers(key);


--
-- Name: connections connections_byoc_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_byoc_credential_id_fkey FOREIGN KEY (byoc_credential_id) REFERENCES public.byoc_credentials(id) ON DELETE SET NULL;


--
-- Name: connections connections_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: connections connections_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: connections connections_provider_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_provider_key_fkey FOREIGN KEY (provider_key) REFERENCES public.oauth_providers(key);


--
-- Name: identities identities_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: permission_rules permission_rules_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission_rules
    ADD CONSTRAINT permission_rules_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: permission_rules permission_rules_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission_rules
    ADD CONSTRAINT permission_rules_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: secret_versions secret_versions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: secret_versions secret_versions_secret_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_secret_id_fkey FOREIGN KEY (secret_id) REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.webhook_subscriptions(id) ON DELETE CASCADE;


--
-- Name: webhook_subscriptions webhook_subscriptions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict YJ2nPdNQU3lkbTpvJENgOzIz7JgnAmgbztuagCojNYBowFARNyGwx2ZkDgf0s1v

