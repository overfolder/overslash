-- Retire the bespoke enrollment flows in favour of MCP OAuth 2.1.
-- Flow 1 (enrollment tokens) and Flow 2 (pending enrollments) are both
-- removed; the only remaining enrollment path is `/oauth/authorize` +
-- `/oauth/consent` as documented in docs/design/mcp-oauth-transport.md.
DROP TABLE IF EXISTS pending_enrollments CASCADE;
DROP TABLE IF EXISTS enrollment_tokens CASCADE;
