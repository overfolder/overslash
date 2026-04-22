-- OAuth services no longer carry a fallback `default_secret_name` on their
-- templates. Any pre-existing `service_instances.secret_name` value on an
-- OAuth-only template is now dead data the resolver will never read. Left in
-- place it would still short-circuit `credentialStatus` in the dashboard to
-- "connected" without a live OAuth connection. NULL it out for the shipped
-- OAuth templates so the UI reflects the real credential state.
UPDATE service_instances
SET secret_name = NULL, updated_at = now()
WHERE secret_name IS NOT NULL
  AND template_key IN (
    'google_calendar',
    'gmail',
    'google_drive',
    'slack',
    'github',
    'eventbrite',
    'x'
  );
