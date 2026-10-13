# Response sizes: tuning the buffering caps against a real client

Use this when a client keeps hitting `response_too_large` (502) or cropped
results, and you want to know what `MAX_RESPONSE_BODY_BYTES` (default 5 MB)
and `CALL_RESULT_MAX_BYTES` (default 1 MB) would have to be to cover their
traffic. The fields are described in
[`docs/design/large-file-handling.md`](../design/large-file-handling.md#measuring-it).

## Fleet-wide: the histogram

`overslash_action_response_bytes{template_key, runtime, read}`. Its bucket
edges are the caps, so the share over each is exact:

```promql
# share of buffered HTTP responses over the 5 MB cap, per template, last 7d
1 - (
  sum by (template_key) (increase(overslash_action_response_bytes_bucket{runtime="http", le="5242880"}[7d]))
  / sum by (template_key) (increase(overslash_action_response_bytes_count{runtime="http"}[7d]))
)
```

`read="aborted_at_cap"` samples are the declared size when the upstream sent
one and a floor otherwise; `runtime="download"` samples are the bytes that
actually flowed through a stream or a redeemed download URL.

## One client: the audit log

The histogram has no org label (cardinality), so per-client numbers come from
`audit_log`. Run against the DB that client lives on (see the dev/prod DB
access notes — prod is not reachable from agent sessions).

```sql
-- Size distribution per service/action for one org, last 14 days.
-- best_bytes = the true size where known, else the floor we read.
WITH s AS (
  SELECT detail->>'service' AS service,
         detail->>'action'  AS action,
         detail->'size'->>'read' AS read,
         detail->'size'->'content_length' = 'null'::jsonb AS no_length,
         COALESCE((detail->'size'->>'content_length')::bigint,
                  (detail->'size'->>'bytes')::bigint) AS best_bytes
  FROM audit_log
  WHERE org_id = $1
    AND action IN ('action.executed', 'action.streamed')
    AND detail ? 'size'
    AND created_at > now() - interval '14 days'
)
SELECT service, action, count(*) AS calls,
       percentile_disc(0.50) WITHIN GROUP (ORDER BY best_bytes) AS p50,
       percentile_disc(0.90) WITHIN GROUP (ORDER BY best_bytes) AS p90,
       percentile_disc(0.99) WITHIN GROUP (ORDER BY best_bytes) AS p99,
       max(best_bytes) AS max,
       count(*) FILTER (WHERE read = 'aborted_at_cap') AS over_cap,
       count(*) FILTER (WHERE read = 'aborted_at_cap' AND no_length) AS over_cap_floor_only
FROM s
GROUP BY 1, 2
ORDER BY calls DESC;
```

Over-cap calls whose upstream sent no `Content-Length` (any chunked
response) only have a floor. Their true size shows up if the
client redeemed the `download_url` the 502 handed back:

```sql
SELECT detail->>'service' AS service, detail->>'action' AS action,
       count(*) AS transfers,
       percentile_disc(0.90) WITHIN GROUP (ORDER BY (detail->>'bytes_streamed')::bigint) AS p90,
       max((detail->>'bytes_streamed')::bigint) AS max,
       count(*) FILTER (WHERE (detail->>'completed')::boolean IS NOT TRUE) AS cut_short
FROM audit_log
WHERE org_id = $1
  AND action = 'action.stream_completed'
  AND created_at > now() - interval '14 days'
GROUP BY 1, 2
ORDER BY transfers DESC;
```

## Reading the answer

- **Raise `MAX_RESPONSE_BODY_BYTES`** only to a value that covers the p90–p99
  of `best_bytes` for the actions that actually need inline bodies. Above
  that, a bigger buffer just moves more bytes into a context window; the
  right answer is `deliver: "url"`, paging, or a `filter`.
- **Raise `CALL_RESULT_MAX_BYTES`** when many cropped calls (`bytes > 8192`
  on a compact render) sit between 1 MB and the response cap — those got no
  `_full_result` link and had to re-run upstream.
- Both are env vars on the API service; no migration, no restart beyond the
  deploy.
