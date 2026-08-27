# Generic pagination

**Status:** Implemented (D-NEXT)

Companion to [large-file-handling.md](large-file-handling.md), which bounds a
response *after* it is too big. This bounds it before.

## The problem, precisely

Overslash had no notion of a page. Every template spelled paging however its
upstream did, the gateway read none of it, and nothing anywhere in the codebase
parsed a `Link` header, followed a `nextPageToken`, or looped.

Six spellings of page size across the shipped corpus:

| spelling | templates |
|---|---|
| `per_page` | github |
| `limit` | stripe, slack, hubspot, whatsapp, metabase, email |
| `page_size` | notion (a body property on a POST) |
| `maxResults` | gmail, google_calendar, google_tasks |
| `pageSize` | google_drive, google_keep |
| `$top` | outlook (OData) |

Six for continuation: `cursor` (slack), `start_cursor` (notion), `pageToken`
(gmail, drive, keep), `offset` (hubspot, metabase), `$skip` (outlook), `page`
(whatsapp), and the `Link` header nobody modelled at all.

And `default:` — the field that decides whether a page size does anything when
the agent omits it, because `validate_input::apply_defaults` injects it into the
arg map at call time — was present on only a handful. Seventeen of thirty-six
HTTP-runtime list operations declared no bound whatsoever.

The failure that prompted this: an agent asked which Metabase cards were
popular, found `run_card` (one card) and `list_cards` (all 2,033), and blew the
5 MB transport cap. D57 fixed that template. The same shape is still waiting in
`eventbrite.list_event_attendees` — an unbounded collection of rich objects,
which is the severe form.

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
- **The corpus sweep.** `gmail.yaml` is the only shipped template annotated.
  See the follow-up issue; it closes with a gate shaped like
  `registry::tests::shipped_mutating_actions_declare_disclose`.
