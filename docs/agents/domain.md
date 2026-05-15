# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

Overslash uses a **two-tier decision system**, not the canonical `docs/adr/` layout. Read both tiers when looking for prior decisions.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root if it exists — domain glossary.
- **`DECISIONS.md`** at the repo root — short, numbered, settled architectural decisions (`D1`, `D2`, …). Each entry has Date / Decision / Rationale, sometimes with a pointer to a longer design doc. This is the authoritative log of what's been decided.
- **`docs/design/`** — long-form design documents. Read **`docs/design/INDEX.md`** first; it lists every doc with a Status column. Use Status to weight what you read:
  - **Implemented / Approved / Shipped** → binding, treat as current truth.
  - **Superseded / Rejected** → historical context only; don't act on them. The INDEX often names the doc that supersedes them.
  - **Draft / Not Implemented** → tentative, useful for understanding intent but not a settled decision.

If `CONTEXT.md` doesn't exist yet, **proceed silently**. Don't flag its absence; don't suggest creating it upfront. The producer skill (`/grill-with-docs`) creates it lazily when terms actually get resolved.

## When you reach a new decision

Use the existing two-tier convention — don't introduce a `docs/adr/` directory.

- **Short decision** ("we chose X over Y because Z," fits in ~5 lines): append a new `D<N>` entry to `DECISIONS.md` following the existing format (Date / Decision / Rationale). Number it sequentially.
- **Long-form decision** (alternatives explored, tradeoffs discussed, multiple subsystems involved): write a new file under `docs/design/<slug>.md`, then add a row to `docs/design/INDEX.md` with an appropriate Status. If the design doc produces a binding choice, also add a one-line `D<N>` entry to `DECISIONS.md` that points at the design doc — that's the existing pattern (see D2 → `nango-integration.md`).

When a previously-settled decision changes:
- Update its `D<N>` entry in `DECISIONS.md` (or add a new one that supersedes it, with a pointer).
- If a design doc backed it, update the design doc's Status in `docs/design/INDEX.md` to `Superseded` and link the replacement.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

## Flag conflicts with prior decisions

If your output contradicts an entry in `DECISIONS.md` or an Implemented/Approved/Shipped design doc, surface it explicitly rather than silently overriding:

> _Contradicts D2 (replace Nango with native OAuth) — but worth reopening because…_
> _Contradicts `docs/design/platform-runtime.md` (Implemented) — but worth reopening because…_

## File structure

```
/
├── CONTEXT.md                          ← domain glossary (created lazily)
├── DECISIONS.md                        ← short, numbered decision log
└── docs/
    └── design/
        ├── INDEX.md                    ← status table for all design docs
        ├── overslash.md
        ├── platform-runtime.md
        └── …
```
