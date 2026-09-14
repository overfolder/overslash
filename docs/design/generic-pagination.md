# Generic pagination

**Status:** Implemented (D75); swept onto the shipped corpus and extended to
the MCP runtime in D78

Companion to [large-file-handling.md](large-file-handling.md), which bounds a
response *after* it is too big. This bounds it before.

## The problem, precisely

Overslash had no notion of a page. Every template spelled paging however its
upstream did, the gateway read none of it, and nothing anywhere in the codebase
parsed a `Link` header, followed a `nextPageToken`, or looped.

Eight spellings of page size across the shipped corpus — six were visible when
this was written, and the sweep turned up two more, which is the argument for
`page_size.param` naming whatever the parameter is called rather than the
vocabulary trying to enumerate them:

| spelling | templates |
|---|---|
| `per_page` | github |
| `limit` | stripe, slack, hubspot, whatsapp, metabase, email |
| `page_size` | notion (a body property on a POST) |
| `maxResults` | gmail, google_calendar, google_tasks |
| `pageSize` | google_drive, google_keep |
| `$top` | outlook (OData) |
| `count` | slack `search_messages` |
| `max_results` | x |

Six for continuation: `cursor` (slack), `start_cursor` (notion), `pageToken`
(gmail, drive, keep), `offset` (hubspot, metabase), `$skip` (outlook), `page`
(whatsapp), and the `Link` header nobody modelled at all.

And `default:` — the field that decides whether a page size does anything when
the agent omits it, because `validate_input::apply_defaults` injects it into the
arg map at call time — was present on only a handful. Seventeen of thirty-six
HTTP-runtime list operations declared no bound whatsoever.

The failure that prompted this: an agent asked which Metabase cards were
popular, found `run_card` (one card) and `list_cards` (all 2,033), and blew the
5 MB transport cap. D57 fixed that template. The same shape was waiting in
`eventbrite.list_event_attendees` — an unbounded collection of rich objects,
which is the severe form — until the corpus sweep below reached it.

## The extension

```yaml
paths:
  /gmail/v1/users/{userId}/messages:
    get:
      operationId: list_messages
      pagination:                 # alias for x-overslash-pagination
        page_size:
          param: maxResults       # must name a declared numeric param
          default: 100            # seeds that param's own `default:`
          max: 500                # declarative; the gateway does not clamp
        next:
          style: cursor           # cursor | offset | page | link
          param: pageToken        # where the continuation goes on the next call
          from: nextPageToken     # dotted body path (cursor only)
        items: messages           # optional: the principal collection
        has_more: null            # optional: an explicit boolean the upstream sends
```

| style | continuation value | maps |
|---|---|---|
| `cursor` | dotted body path in `from` | slack, notion, gmail, drive, keep |
| `offset` | previous offset + effective page size | hubspot, outlook `$skip`, metabase |
| `page` | previous page + 1 | whatsapp |
| `link` | RFC 8288 `rel="next"` header | github |

`page` requires its parameter to declare a `default:`. A page ordinal has no
universal origin — WhatsApp counts from 0, GitHub from 1 — and that default is
the only place a template says which. Without it the gateway cannot compute page
two, so it stops at page one and reports `has_more: false`: a partial answer
that reads as a complete one. The runtime deliberately does *not* fall back to
0 the way the `offset` arm can: an offset of 0 means "from the start"
everywhere, but a guessed page of 0 against a 1-based upstream makes `next`
point at the page just fetched, and a follower loops forever. A traversal that
stops early is a bounded mistake; one that never terminates is not.

`link` is refused on an MCP tool at compile: a tool result is a JSON-RPC
envelope with no response headers, so the declaration would parse and then find
nothing — a silent no-op one layer deeper than D67's extension lint can see.

## Two decisions worth the words

### The page size reuses `apply_defaults` rather than adding a pass

`page_size.default` seeds `ActionParam.default` at compile time when the
parameter declares none. Nothing new runs at call time.

This matters more than it looks. There is one precedence order —
`caller > instance.config > layer instance_defaults > template default` — and
adding a second injection would have made it two. It also means the injected
bound is *discoverable*: D57 already puts `ParamInfo.default` on `/v1/search`
rows, so an agent sees the page size before it calls, without the search
projection learning anything about pagination.

The cost: when a parameter declares its own `default:`, the number written in
the extension is inert. That is a warning (`pagination_default_shadowed`), not
an error — the parameter is the more specific statement and the one an org
layer patches — but it reads as a promise, so it is worth saying out loud.

### `next` is a ready-to-call arg map

```json
"_pagination": {
  "has_more": true,
  "next": {
    "service": "gmail",
    "action": "list_messages",
    "params": { "pageToken": "CAUQ…", "maxResults": 100 }
  }
}
```

The alternative was an opaque gateway-minted token passed back as a reserved
argument. It hides the upstream's vocabulary more completely and costs a decode
path, a tamper surface, and an argument in no action's declared schema — so
`validate_args` needs an exception and the dashboard's API Explorer cannot
replay it. An arg map costs none of that, and an agent can read what it is about
to send.

`params` is the **delta**, not the full effective argument set — the caller
merges it into what it sent. Two reasons: bytes, inside an 8 KB compact budget
where every field competes with rows; and disclosure, since echoing the whole
set would put resolved instance-config pins and filter arguments back into a
model's context on every page.

`{"has_more": false}` with no `next` is emitted rather than nothing, so the
caller can tell "last page" from "the cursor went missing" — the same
distinction D74 exists to protect one layer down.

## Where it runs

`services::pagination::next_page` is pure: spec + the arguments the call went
out with + the `ActionResult`. It reads `body` and `headers` **as they
arrived** — never `filtered_body`, so a jq filter that projects the rows away
does not also cost the caller the page, and never the compact render, whose job
is to drop things.

`routes::actions::render_stored` is the single funnel all four dispatch forks
pass through, and it builds the marker once so the verbose and compact shapes
carry the identical object. The marker is handed *into* `compact` rather than
stamped after it, so its bytes are measured inside the budget — the discipline
D74 established for preserved headers.

### A stored call has to be told

`routes::actions::render_stored` covers the four inline dispatch forks. It does
not cover the two that run later — the async worker's job and an approval replay
— because both start from a `StoredCallRequest`, which holds a *resolved*
request. By then the action key and the argument map are gone.

`StoredCallRequest.timeout_ms` already records this wall in its own doc comment:
"replay cannot re-run the cascade: it has the request but not the action key the
template rungs were read from." Pagination hits it twice over, needing the
argument map too, so `StoredPagination { spec, service, action, params }` rides
on the payload and `stored_call::run_http` / `run_mcp` stamp `_pagination` where
`render_stored` would have.

Payloads written before the field existed parse to `None` and replay exactly as
they did. Platform actions carry nothing, because `ext::READS` does not admit
the key at `Pos::PlatformAction` — a platform action answers from this process,
so there is no upstream page to be on.

## Deliberately absent

- **Auto-follow.** The gateway never loops. Looping multiplies latency,
  per-page approvals and the size cap by a page count nobody chose, and needs a
  stopping rule that is a fact about the caller's task.
- **Clamping.** `max` bounds `default` at validation time and writes the
  dashboard tooltip. A caller who explicitly asks for more gets what it asked
  for; upstreams reject or clamp an oversized page themselves, and silently
  rewriting an explicit argument is indistinguishable from a bug.
- **`deliver: "url"` / `Prefer: stream`.** Both return before the render funnel,
  so neither carries `_pagination`. That envelope holds a download token rather
  than rows.
- **Auto-following, still.** The sweep annotated the corpus; it did not change
  who decides when to stop.

## An MCP tool's paths address the tool, not the envelope

`mcp_caller::invoke` packs every tool result into a stable frame —
`{runtime, tool, structured, content, is_error}` — so for an MCP action the
bytes `next_page` parses are the gateway's bookkeeping, not the payload the
template author is looking at. `next_page` therefore unwraps it first, with the
projection D55 already settled for `x-overslash-resolve`: `structuredContent`
when the server sends it, otherwise the first text content block parsed as
JSON. `pick:` and `from:` mean the same thing against the same server, which is
the only rule a template author can hold in their head.

The alternative — making every MCP template spell `structured.` — asks authors
to know a frame no upstream documents, and still fails on the servers that emit
only a text block. D55's own rationale is that servers differ on which they emit
*for the same tool*, so a template cannot be authored against it.

All three frame keys are required before anything is unwrapped: an HTTP body
that happens to carry `runtime` is a body like any other.

## The sweep, and the two shapes it could not express

Every shipped list action now declares the key or appears in
`registry::tests::shipped_list_actions_declare_pagination`'s `ALLOW_MISSING`
with a comment naming the upstream reason. The gate calls an action list-shaped
on either of two signals: the key (`list_*`, `search*`, `query_*`, plus
Metabase's two activity feeds), or a declared numeric parameter under one of the
seven page-size spellings. The second is what catches the actions that read as
single-object gets — `slack.read_channel_history`, `whatsapp.get_conversation`,
`x.get_user_tweets`.

Two upstreams do not fit, and neither widened the vocabulary:

- **Stripe** continues with `starting_after=<id of the last object on the
  page>`. That is an array-indexed body position, and `dotted` takes no indices
  on purpose. `list_charges` and `list_customers` are bounded by `limit` and
  declare `starting_after`, so a caller can walk them; the gateway cannot
  compute the next call and says so in the description.
- **`email.search`** has a page size and no continuation whatsoever. That is
  what `parse_pagination` refuses by design — a page size with no way to reach
  page two is a limit. `limit` gained a `default: 50`, and `total` is what tells
  a caller what it has not seen.

Nine actions declare a style and no `items`: seven WhatsApp tools and two
HubSpot ones, whose result shapes belong to a container an operator runs or a
vendor's server, and are not verifiable from this repo. A guessed path behaves
exactly like an absent one — `structural_has_more` treats a path resolving to
nothing as a fact about the template — so guessing asserts something false and
buys nothing. The cost is one empty call at the end of a traversal, and a
`pagination_unbounded_end` warning that says so.
