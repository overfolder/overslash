--
-- PostgreSQL database dump
--

\restrict JdtwU9YfjhceOLJB43bpzrmwjQMtMhbQj8i1OaX5U7MyRKK7zcXa56tc3xNHJ36

-- Dumped from database version 16.13 (Debian 16.13-1.pgdg12+1)
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
    identity_id uuid NOT NULL,
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
    disclosed_fields jsonb,
    replay_payload jsonb,
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
    description text,
    impersonated_by_identity_id uuid
);


--
-- Name: byoc_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.byoc_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
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
-- Name: enabled_global_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enabled_global_templates (
    org_id uuid NOT NULL,
    template_key text NOT NULL,
    enabled_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.executions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    approval_id uuid NOT NULL,
    org_id uuid NOT NULL,
    status text NOT NULL,
    remember boolean DEFAULT false NOT NULL,
    remember_keys text[],
    remember_rule_ttl timestamp with time zone,
    result jsonb,
    error text,
    triggered_by text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    result_viewed_at timestamp with time zone,
    CONSTRAINT executions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'executing'::text, 'executed'::text, 'failed'::text, 'cancelled'::text, 'expired'::text])))
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
    is_system boolean DEFAULT false NOT NULL,
    system_kind text,
    owner_identity_id uuid,
    CONSTRAINT groups_owner_only_for_self CHECK (((system_kind = 'self'::text) = (owner_identity_id IS NOT NULL))),
    CONSTRAINT groups_system_kind_check CHECK ((system_kind = ANY (ARRAY['everyone'::text, 'admins'::text, 'self'::text])))
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
    is_org_admin boolean DEFAULT false NOT NULL,
    user_id uuid,
    auto_call_on_approve boolean DEFAULT true NOT NULL,
    CONSTRAINT identities_is_org_admin_only_user CHECK (((kind = 'user'::text) OR (is_org_admin = false))),
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
-- Name: mcp_client_agent_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_client_agent_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    user_identity_id uuid NOT NULL,
    client_id text NOT NULL,
    agent_identity_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    elicitation_enabled boolean DEFAULT false NOT NULL
);


--
-- Name: mcp_refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id text NOT NULL,
    identity_id uuid NOT NULL,
    org_id uuid NOT NULL,
    hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    replaced_by_id uuid
);


--
-- Name: mcp_upstream_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_upstream_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    identity_id uuid NOT NULL,
    org_id uuid NOT NULL,
    upstream_resource text NOT NULL,
    upstream_client_id text NOT NULL,
    status text DEFAULT 'pending_auth'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_refreshed_at timestamp with time zone,
    CONSTRAINT mcp_upstream_connections_status_check CHECK ((status = ANY (ARRAY['pending_auth'::text, 'ready'::text, 'revoked'::text, 'error'::text])))
);


--
-- Name: mcp_upstream_flows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_upstream_flows (
    id text NOT NULL,
    identity_id uuid NOT NULL,
    org_id uuid NOT NULL,
    upstream_resource text NOT NULL,
    upstream_client_id text NOT NULL,
    upstream_as_issuer text NOT NULL,
    upstream_token_endpoint text NOT NULL,
    upstream_authorize_url text NOT NULL,
    pkce_code_verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_ip text,
    created_user_agent text
);


--
-- Name: mcp_upstream_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_upstream_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    connection_id uuid NOT NULL,
    access_token_ciphertext bytea NOT NULL,
    refresh_token_ciphertext bytea,
    access_token_expires_at timestamp with time zone,
    scope text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    superseded_at timestamp with time zone
);


--
-- Name: oauth_connection_flows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_connection_flows (
    id text NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    actor_identity_id uuid NOT NULL,
    provider_key text NOT NULL,
    byoc_credential_id uuid,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    pkce_code_verifier text,
    upstream_authorize_url text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_ip text,
    created_user_agent text
);


--
-- Name: oauth_handoff_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_handoff_codes (
    code text NOT NULL,
    jwt text NOT NULL,
    origin text NOT NULL,
    next_path text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone
);


--
-- Name: oauth_mcp_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_mcp_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id text NOT NULL,
    client_name text,
    redirect_uris text[] NOT NULL,
    software_id text,
    software_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    created_ip text,
    created_user_agent text,
    is_revoked boolean DEFAULT false NOT NULL,
    capabilities jsonb,
    client_info jsonb,
    protocol_version text,
    last_session_id uuid
);


--
-- Name: oauth_preview_origins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_preview_origins (
    preview_id uuid NOT NULL,
    origin text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    nonce text DEFAULT ''::text NOT NULL,
    pkce_verifier text,
    org_slug text,
    next_path text
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
    encrypted_client_id bytea,
    encrypted_client_secret bytea,
    enabled boolean DEFAULT true NOT NULL,
    allowed_email_domains text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    CONSTRAINT org_idp_configs_creds_both_or_neither CHECK ((((encrypted_client_id IS NULL) AND (encrypted_client_secret IS NULL)) OR ((encrypted_client_id IS NOT NULL) AND (encrypted_client_secret IS NOT NULL))))
);


--
-- Name: org_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_subscriptions (
    org_id uuid NOT NULL,
    stripe_subscription_id text NOT NULL,
    stripe_customer_id text NOT NULL,
    plan text DEFAULT 'team'::text NOT NULL,
    seats integer DEFAULT 2 NOT NULL,
    status text NOT NULL,
    currency text NOT NULL,
    current_period_start timestamp with time zone,
    current_period_end timestamp with time zone,
    cancel_at_period_end boolean DEFAULT false NOT NULL,
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
    allow_user_templates boolean DEFAULT false NOT NULL,
    global_templates_enabled boolean DEFAULT true NOT NULL,
    allow_unsigned_secret_provide boolean DEFAULT true NOT NULL,
    is_personal boolean DEFAULT false NOT NULL,
    plan text DEFAULT 'standard'::text NOT NULL,
    default_deferred_execution boolean DEFAULT false NOT NULL,
    CONSTRAINT orgs_approval_auto_bubble_secs_check CHECK ((approval_auto_bubble_secs >= 0)),
    CONSTRAINT orgs_plan_check CHECK ((plan = ANY (ARRAY['standard'::text, 'free_unlimited'::text])))
);


--
-- Name: pending_checkouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_checkouts (
    id text NOT NULL,
    user_id uuid NOT NULL,
    org_name text NOT NULL,
    org_slug text NOT NULL,
    seats integer NOT NULL,
    currency text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '02:00:00'::interval) NOT NULL,
    fulfilled_org_id uuid
);


--
-- Name: pending_mcp_elicitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_mcp_elicitations (
    elicit_id text NOT NULL,
    session_id uuid NOT NULL,
    agent_identity_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    final_response jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
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
-- Name: secret_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_requests (
    id text NOT NULL,
    org_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    secret_name text NOT NULL,
    requested_by uuid NOT NULL,
    reason text,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    fulfilled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    require_user_session boolean DEFAULT false NOT NULL
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
    created_by uuid,
    provisioned_by_user_id uuid
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
-- Name: service_action_embeddings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_action_embeddings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tier text NOT NULL,
    org_id uuid,
    owner_identity_id uuid,
    template_key text NOT NULL,
    action_key text NOT NULL,
    source_text text NOT NULL,
    embedding public.vector(384) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT service_action_embeddings_tier_check CHECK ((tier = ANY (ARRAY['global'::text, 'org'::text, 'user'::text])))
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
    url text,
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
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    openapi jsonb NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    CONSTRAINT service_templates_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'active'::text])))
);


--
-- Name: user_org_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_org_memberships (
    user_id uuid NOT NULL,
    org_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_org_memberships_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'member'::text])))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text,
    display_name text,
    overslash_idp_provider text,
    overslash_idp_subject text,
    personal_org_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    stripe_customer_id text,
    is_instance_admin boolean DEFAULT false NOT NULL,
    CONSTRAINT users_instance_admin_requires_overslash_idp CHECK (((NOT is_instance_admin) OR (overslash_idp_provider IS NOT NULL)))
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
-- Name: enabled_global_templates enabled_global_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enabled_global_templates
    ADD CONSTRAINT enabled_global_templates_pkey PRIMARY KEY (org_id, template_key);


--
-- Name: executions executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.executions
    ADD CONSTRAINT executions_pkey PRIMARY KEY (id);


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
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_pkey PRIMARY KEY (id);


--
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_user_identity_id_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_user_identity_id_client_id_key UNIQUE (user_identity_id, client_id);


--
-- Name: mcp_refresh_tokens mcp_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_refresh_tokens
    ADD CONSTRAINT mcp_refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: mcp_upstream_connections mcp_upstream_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_connections
    ADD CONSTRAINT mcp_upstream_connections_pkey PRIMARY KEY (id);


--
-- Name: mcp_upstream_connections mcp_upstream_connections_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_connections
    ADD CONSTRAINT mcp_upstream_connections_unique UNIQUE (identity_id, upstream_resource);


--
-- Name: mcp_upstream_flows mcp_upstream_flows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_flows
    ADD CONSTRAINT mcp_upstream_flows_pkey PRIMARY KEY (id);


--
-- Name: mcp_upstream_tokens mcp_upstream_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_tokens
    ADD CONSTRAINT mcp_upstream_tokens_pkey PRIMARY KEY (id);


--
-- Name: oauth_connection_flows oauth_connection_flows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_connection_flows
    ADD CONSTRAINT oauth_connection_flows_pkey PRIMARY KEY (id);


--
-- Name: oauth_handoff_codes oauth_handoff_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_handoff_codes
    ADD CONSTRAINT oauth_handoff_codes_pkey PRIMARY KEY (code);


--
-- Name: oauth_mcp_clients oauth_mcp_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_mcp_clients
    ADD CONSTRAINT oauth_mcp_clients_client_id_key UNIQUE (client_id);


--
-- Name: oauth_mcp_clients oauth_mcp_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_mcp_clients
    ADD CONSTRAINT oauth_mcp_clients_pkey PRIMARY KEY (id);


--
-- Name: oauth_preview_origins oauth_preview_origins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_preview_origins
    ADD CONSTRAINT oauth_preview_origins_pkey PRIMARY KEY (preview_id);


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
-- Name: org_subscriptions org_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_pkey PRIMARY KEY (org_id);


--
-- Name: org_subscriptions org_subscriptions_stripe_subscription_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_stripe_subscription_id_key UNIQUE (stripe_subscription_id);


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
-- Name: pending_checkouts pending_checkouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_checkouts
    ADD CONSTRAINT pending_checkouts_pkey PRIMARY KEY (id);


--
-- Name: pending_mcp_elicitations pending_mcp_elicitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_mcp_elicitations
    ADD CONSTRAINT pending_mcp_elicitations_pkey PRIMARY KEY (elicit_id);


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
-- Name: secret_requests secret_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_requests
    ADD CONSTRAINT secret_requests_pkey PRIMARY KEY (id);


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
-- Name: service_action_embeddings service_action_embeddings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_action_embeddings
    ADD CONSTRAINT service_action_embeddings_pkey PRIMARY KEY (id);


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
-- Name: user_org_memberships user_org_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_org_memberships
    ADD CONSTRAINT user_org_memberships_pkey PRIMARY KEY (user_id, org_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


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
-- Name: idx_approvals_resolver_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_resolver_pending ON public.approvals USING btree (current_resolver_identity_id) WHERE (status = 'pending'::text);


--
-- Name: idx_audit_log_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_identity ON public.audit_log USING btree (identity_id, created_at DESC);


--
-- Name: idx_audit_log_impersonated_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_impersonated_by ON public.audit_log USING btree (org_id, impersonated_by_identity_id) WHERE (impersonated_by_identity_id IS NOT NULL);


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
-- Name: idx_executions_approval_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_executions_approval_id ON public.executions USING btree (approval_id);


--
-- Name: idx_executions_org_status_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_org_status_expires ON public.executions USING btree (org_id, status, expires_at);


--
-- Name: idx_executions_pending_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_pending_expiry ON public.executions USING btree (expires_at) WHERE (status = 'pending'::text);


--
-- Name: idx_executions_unread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_unread ON public.executions USING btree (org_id, completed_at) WHERE ((status = ANY (ARRAY['executed'::text, 'failed'::text])) AND (result_viewed_at IS NULL));


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
-- Name: idx_groups_self_per_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_groups_self_per_user ON public.groups USING btree (org_id, owner_identity_id) WHERE (system_kind = 'self'::text);


--
-- Name: idx_identities_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_archived ON public.identities USING btree (archived_at) WHERE (archived_at IS NOT NULL);


--
-- Name: idx_identities_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_email ON public.identities USING btree (email) WHERE (email IS NOT NULL);


--
-- Name: idx_identities_email_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_email_lookup ON public.identities USING btree (email) WHERE (email IS NOT NULL);


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
-- Name: idx_identities_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identities_user ON public.identities USING btree (user_id);


--
-- Name: idx_identity_groups_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identity_groups_group ON public.identity_groups USING btree (group_id);


--
-- Name: idx_identity_groups_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identity_groups_identity ON public.identity_groups USING btree (identity_id);


--
-- Name: idx_mcp_client_agent_bindings_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_client_agent_bindings_agent ON public.mcp_client_agent_bindings USING btree (agent_identity_id);


--
-- Name: idx_mcp_client_agent_bindings_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_client_agent_bindings_user ON public.mcp_client_agent_bindings USING btree (user_identity_id);


--
-- Name: idx_mcp_refresh_tokens_active_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_refresh_tokens_active_identity ON public.mcp_refresh_tokens USING btree (identity_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_mcp_refresh_tokens_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_refresh_tokens_client ON public.mcp_refresh_tokens USING btree (client_id);


--
-- Name: idx_mcp_refresh_tokens_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mcp_refresh_tokens_hash ON public.mcp_refresh_tokens USING btree (hash);


--
-- Name: idx_mcp_upstream_connections_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_upstream_connections_org ON public.mcp_upstream_connections USING btree (org_id);


--
-- Name: idx_mcp_upstream_flows_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_upstream_flows_expires_at ON public.mcp_upstream_flows USING btree (expires_at) WHERE (consumed_at IS NULL);


--
-- Name: idx_mcp_upstream_flows_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_upstream_flows_identity ON public.mcp_upstream_flows USING btree (identity_id, created_at DESC);


--
-- Name: idx_mcp_upstream_tokens_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mcp_upstream_tokens_current ON public.mcp_upstream_tokens USING btree (connection_id) WHERE (superseded_at IS NULL);


--
-- Name: idx_memberships_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_memberships_org ON public.user_org_memberships USING btree (org_id);


--
-- Name: idx_oauth_connection_flows_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_connection_flows_expires_at ON public.oauth_connection_flows USING btree (expires_at) WHERE (consumed_at IS NULL);


--
-- Name: idx_oauth_connection_flows_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_connection_flows_identity ON public.oauth_connection_flows USING btree (identity_id, created_at DESC);


--
-- Name: idx_oauth_handoff_codes_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_handoff_codes_expires ON public.oauth_handoff_codes USING btree (expires_at);


--
-- Name: idx_oauth_mcp_clients_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_mcp_clients_active ON public.oauth_mcp_clients USING btree (created_at DESC) WHERE (is_revoked = false);


--
-- Name: idx_oauth_preview_origins_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_preview_origins_expires ON public.oauth_preview_origins USING btree (expires_at);


--
-- Name: idx_org_idp_configs_domains; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_idp_configs_domains ON public.org_idp_configs USING gin (allowed_email_domains);


--
-- Name: idx_org_idp_configs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_idp_configs_org ON public.org_idp_configs USING btree (org_id);


--
-- Name: idx_orgs_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_orgs_plan ON public.orgs USING btree (plan) WHERE (plan <> 'standard'::text);


--
-- Name: idx_pending_checkouts_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_checkouts_user ON public.pending_checkouts USING btree (user_id);


--
-- Name: idx_pending_mcp_elicit_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_mcp_elicit_session ON public.pending_mcp_elicitations USING btree (session_id);


--
-- Name: idx_pending_mcp_elicit_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_mcp_elicit_status ON public.pending_mcp_elicitations USING btree (status, created_at);


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
-- Name: idx_secret_requests_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_requests_org ON public.secret_requests USING btree (org_id);


--
-- Name: idx_secret_requests_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_requests_pending ON public.secret_requests USING btree (expires_at) WHERE (fulfilled_at IS NULL);


--
-- Name: idx_secret_versions_provisioned_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_versions_provisioned_by ON public.secret_versions USING btree (provisioned_by_user_id) WHERE (provisioned_by_user_id IS NOT NULL);


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

CREATE UNIQUE INDEX idx_service_templates_org_key ON public.service_templates USING btree (org_id, key) WHERE ((owner_identity_id IS NULL) AND (status = 'active'::text));


--
-- Name: idx_service_templates_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_service_templates_status ON public.service_templates USING btree (status);


--
-- Name: idx_service_templates_user_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_templates_user_key ON public.service_templates USING btree (org_id, owner_identity_id, key) WHERE ((owner_identity_id IS NOT NULL) AND (status = 'active'::text));


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_is_instance_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_instance_admin ON public.users USING btree (is_instance_admin) WHERE is_instance_admin;


--
-- Name: idx_users_personal_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_personal_org ON public.users USING btree (personal_org_id);


--
-- Name: idx_webhook_deliveries_retry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_deliveries_retry ON public.webhook_deliveries USING btree (next_retry_at) WHERE ((delivered_at IS NULL) AND (attempts < 5));


--
-- Name: org_idp_configs_one_default_per_org; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX org_idp_configs_one_default_per_org ON public.org_idp_configs USING btree (org_id) WHERE is_default;


--
-- Name: service_action_embeddings_global_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_action_embeddings_global_unique ON public.service_action_embeddings USING btree (template_key, action_key) WHERE (tier = 'global'::text);


--
-- Name: service_action_embeddings_hnsw; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX service_action_embeddings_hnsw ON public.service_action_embeddings USING hnsw (embedding public.vector_cosine_ops);


--
-- Name: service_action_embeddings_org_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_action_embeddings_org_unique ON public.service_action_embeddings USING btree (org_id, template_key, action_key) WHERE (tier = 'org'::text);


--
-- Name: service_action_embeddings_user_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_action_embeddings_user_unique ON public.service_action_embeddings USING btree (org_id, owner_identity_id, template_key, action_key) WHERE (tier = 'user'::text);


--
-- Name: users_overslash_idp_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_overslash_idp_unique ON public.users USING btree (overslash_idp_provider, overslash_idp_subject) WHERE ((overslash_idp_provider IS NOT NULL) AND (overslash_idp_subject IS NOT NULL));


--
-- Name: users_stripe_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_stripe_customer ON public.users USING btree (stripe_customer_id) WHERE (stripe_customer_id IS NOT NULL);


--
-- Name: api_keys api_keys_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


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
-- Name: audit_log audit_log_impersonated_by_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_impersonated_by_identity_id_fkey FOREIGN KEY (impersonated_by_identity_id) REFERENCES public.identities(id) ON DELETE SET NULL;


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
-- Name: enabled_global_templates enabled_global_templates_enabled_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enabled_global_templates
    ADD CONSTRAINT enabled_global_templates_enabled_by_fkey FOREIGN KEY (enabled_by) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: enabled_global_templates enabled_global_templates_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enabled_global_templates
    ADD CONSTRAINT enabled_global_templates_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: executions executions_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.executions
    ADD CONSTRAINT executions_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.approvals(id) ON DELETE CASCADE;


--
-- Name: executions executions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.executions
    ADD CONSTRAINT executions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


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
-- Name: groups groups_owner_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_owner_identity_id_fkey FOREIGN KEY (owner_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


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
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


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
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_agent_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_agent_identity_id_fkey FOREIGN KEY (agent_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_mcp_clients(client_id) ON DELETE CASCADE;


--
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: mcp_client_agent_bindings mcp_client_agent_bindings_user_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_client_agent_bindings
    ADD CONSTRAINT mcp_client_agent_bindings_user_identity_id_fkey FOREIGN KEY (user_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: mcp_refresh_tokens mcp_refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_refresh_tokens
    ADD CONSTRAINT mcp_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_mcp_clients(client_id) ON DELETE CASCADE;


--
-- Name: mcp_refresh_tokens mcp_refresh_tokens_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_refresh_tokens
    ADD CONSTRAINT mcp_refresh_tokens_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: mcp_refresh_tokens mcp_refresh_tokens_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_refresh_tokens
    ADD CONSTRAINT mcp_refresh_tokens_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: mcp_refresh_tokens mcp_refresh_tokens_replaced_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_refresh_tokens
    ADD CONSTRAINT mcp_refresh_tokens_replaced_by_id_fkey FOREIGN KEY (replaced_by_id) REFERENCES public.mcp_refresh_tokens(id);


--
-- Name: mcp_upstream_connections mcp_upstream_connections_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_connections
    ADD CONSTRAINT mcp_upstream_connections_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: mcp_upstream_connections mcp_upstream_connections_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_connections
    ADD CONSTRAINT mcp_upstream_connections_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: mcp_upstream_flows mcp_upstream_flows_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_flows
    ADD CONSTRAINT mcp_upstream_flows_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: mcp_upstream_flows mcp_upstream_flows_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_flows
    ADD CONSTRAINT mcp_upstream_flows_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: mcp_upstream_tokens mcp_upstream_tokens_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_upstream_tokens
    ADD CONSTRAINT mcp_upstream_tokens_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.mcp_upstream_connections(id) ON DELETE CASCADE;


--
-- Name: oauth_connection_flows oauth_connection_flows_actor_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_connection_flows
    ADD CONSTRAINT oauth_connection_flows_actor_identity_id_fkey FOREIGN KEY (actor_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: oauth_connection_flows oauth_connection_flows_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_connection_flows
    ADD CONSTRAINT oauth_connection_flows_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: oauth_connection_flows oauth_connection_flows_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_connection_flows
    ADD CONSTRAINT oauth_connection_flows_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


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
-- Name: org_subscriptions org_subscriptions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: pending_checkouts pending_checkouts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_checkouts
    ADD CONSTRAINT pending_checkouts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pending_mcp_elicitations pending_mcp_elicitations_agent_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_mcp_elicitations
    ADD CONSTRAINT pending_mcp_elicitations_agent_identity_id_fkey FOREIGN KEY (agent_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: pending_mcp_elicitations pending_mcp_elicitations_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_mcp_elicitations
    ADD CONSTRAINT pending_mcp_elicitations_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.approvals(id) ON DELETE CASCADE;


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
-- Name: secret_requests secret_requests_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_requests
    ADD CONSTRAINT secret_requests_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: secret_requests secret_requests_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_requests
    ADD CONSTRAINT secret_requests_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: secret_requests secret_requests_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_requests
    ADD CONSTRAINT secret_requests_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.identities(id);


--
-- Name: secret_versions secret_versions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.identities(id) ON DELETE SET NULL;


--
-- Name: secret_versions secret_versions_provisioned_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_provisioned_by_user_id_fkey FOREIGN KEY (provisioned_by_user_id) REFERENCES public.identities(id) ON DELETE SET NULL;


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
-- Name: service_action_embeddings service_action_embeddings_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_action_embeddings
    ADD CONSTRAINT service_action_embeddings_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: service_action_embeddings service_action_embeddings_owner_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_action_embeddings
    ADD CONSTRAINT service_action_embeddings_owner_identity_id_fkey FOREIGN KEY (owner_identity_id) REFERENCES public.identities(id) ON DELETE CASCADE;


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
-- Name: user_org_memberships user_org_memberships_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_org_memberships
    ADD CONSTRAINT user_org_memberships_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.orgs(id) ON DELETE CASCADE;


--
-- Name: user_org_memberships user_org_memberships_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_org_memberships
    ADD CONSTRAINT user_org_memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users users_personal_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_personal_org_id_fkey FOREIGN KEY (personal_org_id) REFERENCES public.orgs(id) ON DELETE SET NULL;


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

\unrestrict JdtwU9YfjhceOLJB43bpzrmwjQMtMhbQj8i1OaX5U7MyRKK7zcXa56tc3xNHJ36

