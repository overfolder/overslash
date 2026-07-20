# Credential slots and composition templates

**Status**: Implemented
**Decision**: [D35](../../DECISIONS.md)

## The problem

A securityScheme used to be three things at once: the declaration of a
credential, the vault-lookup key, and the injection site. One scheme = one
secret = one header.

`services/email.yaml` is where that broke. The overfwd gateway wants
`X-Mailbox-Auth: Basic base64(user:pass)`, and the only transforms available
were `x-overslash-encode: base64` and `x-overslash-prefix: "Basic "`, both
applied to one opaque value. So the operator had to store a *single* secret
whose literal value was `user@example.com:app-password`:

- the username and password are fused in the vault, so the password cannot be
  rotated on its own and neither half is separately auditable;
- the dashboard asked for one anonymous field and the user had to know the
  colon convention;
- it generalizes to nothing. `{tenant}\{user}:{pass}`, or one secret feeding
  two headers, each needed another one-off `x-overslash-*` extension.

## The shape

Secrets are declared once; injections are separate and say how to build a
value from them.

```yaml
components:
  x-overslash-secrets:
    mailbox_user:
      label: Mailbox username
      description: The IMAP/SMTP login, usually the full email address.
      source: instance
    mailbox_pass:
      label: Mailbox password
      source: instance
  securitySchemes:
    mailbox:
      type: apiKey
      in: header
      name: X-Mailbox-Auth
      x-overslash-template:
        lang: jq
        expr: '"Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)'
```

A slot may feed several injections; an injection may join several slots. A
scheme with **no** template injects one secret verbatim, and every scheme
implicitly declares a slot named after itself — which is why the 18 shipped
single-secret templates declare no `x-overslash-secrets` block at all. That
implicit-slot rule lives in exactly one place,
`ServiceDefinition::slots_for`, so resolution, status derivation, binding
validation and the dashboard payload cannot drift apart.

Slot keys are flat strings in the existing `credentials jsonb` from
[D32](../../DECISIONS.md), so this needed no migration.

## Why jq and not a small template grammar

`Basic ({user}:{pass} | base64)` reads better in YAML. Everything else
favoured reusing what the product already runs:

| | jq (jaq) | own grammar |
|---|---|---|
| Parser | none to write | ~80 lines + escapes, nesting, unbalanced delimiters |
| Syntax validation at load | `validate_syntax` already exists | new |
| CPU-bomb guard | `spawn_blocking` + timeout + output cap, already built | closed grammar has no such surface |
| Capabilities | `@base64`, `@base64d`, `@uri`, `"\(.a):\(.b)"`, `// "default"`, conditionals | one extension at a time |
| Familiarity | already the language for response filters and disclosures | one more thing to learn |

jaq already ships `@base64`/`@base64d`/`@uri`, so no custom filters were
needed. If one ever is (base64url, HMAC signing), the extension point is the
`Compiler::with_funs(...)` chain in `response_filter::run_jq_blocking` —
append another `funs` iterator.

## Static slot analysis: decrypt only what the header needs

`jaq_core::load::{Lexer, Parser}` and the `parse::Term` AST are public, and
`.mailbox_user` parses to `Term::Path(Id, [Part::Index(Str("mailbox_user"))])`.
So `overslash-core::credential_template::referenced_slots` walks the AST for
literal string indices and returns the exact slot set, in source order.

This runs **once at template-compile time**. The result is stored on the
compiled `ServiceAuth::Secret` (`slots`) and narrowed into each `SecretRef`'s
`bindings` at resolution, so the request path parses no jq to decide what to
decrypt: a template declaring five slots whose header names two decrypts two,
and the evaluator is handed an object containing only those two.

For that guarantee to hold, **dynamic key access is rejected at load time** —
`.[$k]`, `.["a"+"b"]`, `getpath`, `keys`, `to_entries`, `..`. Any of them
could reach a slot the static walk cannot see.

`overslash-core` therefore depends on `jaq-core` (three small deps) for
lexing and parsing only. Evaluation needs `jaq-std`/`jaq-json` and stays in
`overslash-api`, so core never runs a jq program.

## Two hazards of a general evaluator, and what stops them

**1. jq errors quote their operands, and the operands are credentials.**
`run_jq_blocking` formats runtime errors with `format!("{e}")`, so a type
error on secret input can put a password into a log line or an API response.
Nothing in `services::credential_template` lets a jaq error message reach the
caller: every failure — jq error, panic, timeout, wrong output arity,
non-string output — collapses to `"credential template for scheme '<x>'
failed to build a value"`. A test asserts a deliberately type-erroring
expression cannot leak its input. Load-time *syntax* errors are safe to
surface and are: they quote program text, not values.

**2. `"user" + null` is `"user"`, not an error.** Without a guard, a missing
password renders `Basic base64("user:")` — a truncated credential that
authenticates as nobody and looks, from every downstream vantage point,
exactly like a wrong password. `render` therefore refuses to build a value
when any slot the expression reads has no value, and resolution refuses to
emit a scheme unless every slot it reads resolved. The test that pins this
also demonstrates the hazard, so it cannot be "simplified" away.

## What was removed

`x-overslash-prefix` and `x-overslash-encode` are gone from the template
surface, along with `SecretEncoding` and `TokenInjection::encode`. A template
still carrying them fails validation with a message naming the equivalent
`expr` — the error message is the migration guide for org and user templates
in the wild.

Two prefixes survive deliberately, neither of them a template concern:

- `TokenInjection::prefix` for OAuth — a live access token is not a vault
  secret and has no slot to compose.
- `SecretRef::prefix` for raw HTTP (Mode A) — a caller naming a secret inline
  in `secrets: [{name, inject_as, header_name, prefix}]` has no service
  template at all, and that request shape is documented public API.

## Rollout

Breaking, deliberately:

1. Org/user templates carrying the removed extensions fail validation on next
   load.
2. Deployed `email` instances bound to a single `user:pass` secret stop
   resolving and report `needs_authentication` until rebound to
   `mailbox_user` + `mailbox_pass`. Splitting the stored value is a manual,
   one-time step per mailbox.
3. Approvals pending across the deploy keep replaying: `SecretRef` still
   deserialises (and ignores) the old `encode` field.
