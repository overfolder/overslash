-- Per-instance MCP tool discovery. `POST /v1/services/{id}/mcp/resync` calls
-- tools/list against the instance's effective MCP server (instance url/secret
-- wins, template is fallback) and stores the result here. Per-instance rather
-- than on the template because one template (e.g. telegram) fans out to many
-- instances — one fast-mcp container per end-user — each pointing at a
-- different server whose tool list may differ.
--
-- Both columns are nullable: NULL discovered_tools means "never resynced",
-- distinct from an empty list (server exposes no tools). The read-side overlay
-- merges these on top of the template's authored `tools:` (authored wins
-- field-by-field).
ALTER TABLE service_instances
  ADD COLUMN discovered_tools jsonb,
  ADD COLUMN discovered_at    timestamptz;

COMMENT ON COLUMN service_instances.discovered_tools IS
  'MCP tools/list result for this instance (array of {name, description, input_schema, output_schema}). NULL = never resynced. Overlaid on the template''s authored tools at read time.';
