--
-- PostgreSQL database dump
--

\restrict PoNQ2g6Ub70cpB53XNupqXZUBvsJBZz80zpBlBkBEcfgAH9sbCJGvpoadlYok7l

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
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_reason text
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
    current_resolver_identity_id uuid NOT NULL,
    resolver_assigned_at timestamp with time zone DEFAULT now() NOT NULL,
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
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    description text
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
-- Name: enrollment_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrollment_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_prefix character varying(16) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: group_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    service_instance_id uuid NOT NULL,
    access_level text NOT NULL,
    auto_approve_reads boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_grants_access_level_check CHECK ((access_level = ANY (ARRAY['read'::text, 'write'::text, 'admin'::text])))
);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    allow_raw_http boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_system boolean DEFAULT false NOT NULL
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
    email text,
    parent_id uuid,
    depth integer DEFAULT 0 NOT NULL,
    owner_id uuid,
    inherit_permissions boolean DEFAULT false NOT NULL,
    last_active_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone,
    archived_reason text,
    preferences jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT identities_kind_check CHECK ((kind = ANY (ARRAY['user'::text, 'agent'::text, 'sub_agent'::text])))
);


--
-- Name: identity_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_groups (
    identity_id uuid NOT NULL,
    group_id uuid NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL
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
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    token_auth_method text DEFAULT 'client_secret_post'::text NOT NULL,
    issuer_url text,
    jwks_uri text
);


--
-- Name: org_idp_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_idp_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    provider_key text NOT NULL,
    encrypted_client_id bytea NOT NULL,
    encrypted_client_secret bytea NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    allowed_email_domains text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: orgs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orgs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    subagent_idle_timeout_secs integer DEFAULT 14400 NOT NULL,
    subagent_archive_retention_days integer DEFAULT 30 NOT NULL,
    approval_auto_bubble_secs integer DEFAULT 300 NOT NULL,
    CONSTRAINT orgs_approval_auto_bubble_secs_check CHECK ((approval_auto_bubble_secs >= 0))
);


--
-- Name: pending_enrollments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_enrollments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    suggested_name text NOT NULL,
    platform text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    approval_token text NOT NULL,
    poll_token_hash text NOT NULL,
    poll_token_prefix character varying(16) NOT NULL,
    org_id uuid,
    identity_id uuid,
    api_key_hash text,
    api_key_prefix character varying(16),
    approved_by uuid,
    final_name text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    requester_ip text,
    CONSTRAINT pending_enrollments_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text, 'expired'::text])))
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
    expires_at timestamp with time zone,
    CONSTRAINT permission_rules_effect_check CHECK ((effect = ANY (ARRAY['allow'::text, 'deny'::text])))
);


--
-- Name: rate_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_limits (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid,
    group_id uuid,
    scope text NOT NULL,
    max_requests integer DEFAULT 1000 NOT NULL,
    window_seconds integer DEFAULT 60 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT rate_limits_scope_check CHECK ((scope = ANY (ARRAY['org'::text, 'group'::text, 'user'::text, 'identity_cap'::text])))
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
-- Name: service_instances; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    owner_identity_id uuid,
    name text NOT NULL,
    template_source text NOT NULL,
    template_key text NOT NULL,
    template_id uuid,
    connection_id uuid,
    secret_name text,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    CONSTRAINT service_instances_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'active'::text, 'archived'::text]))),
    CONSTRAINT service_instances_template_source_check CHECK ((template_source = ANY (ARRAY['global'::text, 'org'::text, 'user'::text])))
);


--
-- Name: service_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    owner_identity_id uuid,
    key text NOT NULL,
    display_name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    category text DEFAULT ''::text NOT NULL,
    hosts text[] DEFAULT '{}'::text[] NOT NULL,
    auth jsonb DEFAULT '[]'::jsonb NOT NULL,
    actions jsonb DEFAULT '{}'::jsonb NOT NULL,
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
-- Name: enrollment_tokens enrollment_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_pkey PRIMARY KEY (id);


--
-- Name: group_grants group_grants_group_id_service_instance_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_grants
    ADD CONSTRAINT group_grants_group_id_service_instance_id_key UNIQUE (group_id, service_instance_id);


--
-- Name: group_grants group_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_grants
    ADD CONSTRAINT group_grants_pkey PRIMARY KEY (id);


--
-- Name: groups groups_org_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_org_id_name_key UNIQUE (org_id, name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


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
-- Name: identity_groups identity_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_groups
    ADD CONSTRAINT identity_groups_pkey PRIMARY KEY (identity_id, group_id);


--
-- Name: oauth_providers oauth_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_providers
    ADD CONSTRAINT oauth_providers_pkey PRIMARY KEY (key);


--
-- Name: org_idp_configs org_idp_configs_org_id_provider_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_idp_configs
    ADD CONSTRAINT org_idp_configs_org_id_provider_key_key UNIQUE (org_id, provider_key);


--
-- Name: org_idp_configs org_idp_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_idp_configs
    ADD CONSTRAINT org_idp_configs_pkey PRIMARY KEY (id);


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
-- Name: pending_enrollments pending_enrollments_approval_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_enrollments
    ADD CONSTRAINT pending_enrollments_approval_token_key UNIQUE (approval_token);


--
-- Name: pending_enrollments pending_enrollments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_enrollments
    ADD CONSTRAINT pending_enrollments_pkey PRIMARY KEY (id);


--
-- Name: permission_rules permission_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission_rules
    ADD CONSTRAINT permission_rules_pkey PRIMARY KEY (id);


--
-- Name: rate_limits rate_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_pkey PRIMARY KEY (id);


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
-- Name: service_instances service_instances_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_instances
    ADD CONSTRAINT service_instances_pkey PRIMARY KEY (id);


--
-- Name: service_templates service_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_templates
    ADD CONSTRAINT service_templates_pkey PRIMARY KEY (id);


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
-- Name: byoc_credentials_org_provider_null_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX byoc_credentials_org_provider_null_identity ON public.byoc_credentials USING btree (org_id, provider_key) WHERE (identity_id IS NULL);


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
-- Name: idx_approvals_resolver_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_resolver_pending ON public.approvals USING btree (current_resolver_identity_id) WHERE (status = 'pending'::text);


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
-- Name: idx_enrollment_tokens_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_enrollment_tokens_prefix ON public.enrollment_tokens USING btree (token_prefix);


--
-- Name: idx_group_grants_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_grants_group ON public.group_grants USING btree (group_id);


--
-- Name: idx_group_grants_service; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_grants_service ON public.group_grants USING btree (service_instance_id);


--
-- Name: idx_groups_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_org ON public.groups USING btree (org_id);


--
-- Name: idx_identities_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_archived ON public.identities USING btree (archived_at) WHERE (archived_at IS NOT NULL);


--
-- Name: idx_identities_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_email ON public.identities USING btree (email) WHERE (email IS NOT NULL);


--
-- Name: idx_identities_idle_subagents; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_idle_subagents ON public.identities USING btree (last_active_at) WHERE ((kind = 'sub_agent'::text) AND (archived_at IS NULL));


--
-- Name: idx_identities_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_org ON public.identities USING btree (org_id);


--
-- Name: idx_identities_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_owner ON public.identities USING btree (owner_id) WHERE (owner_id IS NOT NULL);


--
-- Name: idx_identities_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_parent ON public.identities USING btree (parent_id) WHERE (parent_id IS NOT NULL);


--
-- Name: idx_identities_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_identities_user_email ON public.identities USING btree (email) WHERE ((kind = 'user'::text) AND (email IS NOT NULL));


--
-- Name: idx_identity_groups_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identity_groups_group ON public.identity_groups USING btree (group_id);


--
-- Name: idx_identity_groups_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identity_groups_identity ON public.identity_groups USING btree (identity_id);


--
-- Name: idx_org_idp_configs_domains; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_idp_configs_domains ON public.org_idp_configs USING gin (allowed_email_domains);


--
-- Name: idx_org_idp_configs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_idp_configs_org ON public.org_idp_configs USING btree (org_id);


--
-- Name: idx_pending_enrollments_poll_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_pending_enrollments_poll_prefix ON public.pending_enrollments USING btree (poll_token_prefix);


--
-- Name: idx_pending_enrollments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_enrollments_status ON public.pending_enrollments USING btree (status) WHERE (status = 'pending'::text);


--
-- Name: idx_permission_rules_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_permission_rules_identity ON public.permission_rules USING btree (identity_id);


--
-- Name: idx_rate_limits_group; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_rate_limits_group ON public.rate_limits USING btree (org_id, group_id) WHERE (scope = 'group'::text);


--
-- Name: idx_rate_limits_identity_cap; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_rate_limits_identity_cap ON public.rate_limits USING btree (org_id, identity_id) WHERE (scope = 'identity_cap'::text);


--
-- Name: idx_rate_limits_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rate_limits_org ON public.rate_limits USING btree (org_id);


--
-- Name: idx_rate_limits_org_default; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_rate_limits_org_default ON public.rate_limits USING btree (org_id) WHERE (scope = 'org'::text);


--
-- Name: idx_rate_limits_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_rate_limits_user ON public.rate_limits USING btree (org_id, identity_id) WHERE (scope = 'user'::text);


--
-- Name: idx_secret_versions_secret; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_secret ON public.secret_versions USING btree (secret_id);


--
-- Name: idx_service_instances_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_service_instances_org ON public.service_instances USING btree (org_id);


--
-- Name: idx_service_instances_org_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_instances_org_name ON public.service_instances USING btree (org_id, name) WHERE (owner_identity_id IS NULL);


--
-- Name: idx_service_instances_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_service_instances_owner ON public.service_instances USING btree (owner_identity_id);


--
-- Name: idx_service_instances_user_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_instances_user_name ON public.service_instances USING btree (org_id, owner_identity_id, name) WHERE (owner_identity_id IS NOT NULL);


--
-- Name: idx_service_templates_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_service_templates_org ON public.service_templates USING btree (org_id);


--
-- Name: idx_service_templates_org_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_templates_org_key ON public.service_templates USING btree (org_id, key) WHERE (owner_identity_id IS NULL);


--
-- Name: idx_service_templates_user_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_templates_user_key ON public.service_templates USING btree (org_id, owner_identity_id, key) WHERE (owner_identity_id IS NOT NULL);


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
-- Name: approvals approvals_current_resolver_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_current_resolver_identity_id_fkey FOREIGN KEY (current_resolver_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


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
-- Name: enrollment_tokens enrollment_tokens_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.identities(id);


--
-- Name: enrollment_tokens enrollment_tokens_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: enrollment_tokens enrollment_tokens_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: group_grants group_grants_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_grants
    ADD CONSTRAINT group_grants_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: group_grants group_grants_service_instance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_grants
    ADD CONSTRAINT group_grants_service_instance_id_fkey FOREIGN KEY (service_instance_id) REFERENCES public.service_instances(id) ON DELETE CASCADE;


--
-- Name: groups groups_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: identities identities_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: identities identities_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: identities identities_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_groups identity_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_groups
    ADD CONSTRAINT identity_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: identity_groups identity_groups_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_groups
    ADD CONSTRAINT identity_groups_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: org_idp_configs org_idp_configs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_idp_configs
    ADD CONSTRAINT org_idp_configs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: org_idp_configs org_idp_configs_provider_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_idp_configs
    ADD CONSTRAINT org_idp_configs_provider_key_fkey FOREIGN KEY (provider_key) REFERENCES public.oauth_providers(key);


--
-- Name: pending_enrollments pending_enrollments_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_enrollments
    ADD CONSTRAINT pending_enrollments_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.identities(id);


--
-- Name: pending_enrollments pending_enrollments_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_enrollments
    ADD CONSTRAINT pending_enrollments_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id);


--
-- Name: pending_enrollments pending_enrollments_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_enrollments
    ADD CONSTRAINT pending_enrollments_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id);


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
-- Name: rate_limits rate_limits_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: rate_limits rate_limits_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: rate_limits rate_limits_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


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
-- Name: service_instances service_instances_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_instances
    ADD CONSTRAINT service_instances_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.connections(id) ON DELETE SET NULL;


--
-- Name: service_instances service_instances_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_instances
    ADD CONSTRAINT service_instances_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: service_instances service_instances_owner_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_instances
    ADD CONSTRAINT service_instances_owner_identity_id_fkey FOREIGN KEY (owner_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: service_instances service_instances_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_instances
    ADD CONSTRAINT service_instances_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.service_templates(id) ON DELETE SET NULL;


--
-- Name: service_templates service_templates_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_templates
    ADD CONSTRAINT service_templates_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: service_templates service_templates_owner_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_templates
    ADD CONSTRAINT service_templates_owner_identity_id_fkey FOREIGN KEY (owner_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


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

\unrestrict PoNQ2g6Ub70cpB53XNupqXZUBvsJBZz80zpBlBkBEcfgAH9sbCJGvpoadlYok7l

