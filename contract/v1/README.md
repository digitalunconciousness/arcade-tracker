# GATBOX → hub contract, v1

The wire format between GATBOX (a Raspberry Pi running the bench diagnostics) and this
application, the hub. **One direction only: GATBOX pushes, the hub never connects to GATBOX.**

This directory is owned by the hub and vendored into GATBOX at `docs/contract/v1/`. Both
copies are checked against `CHECKSUMS` by a test in each repository, so they cannot drift
apart without something going red.

## The examples are the schema

GATBOX is stdlib-only and neither side carries a JSON Schema validator, so the files under
`examples/` are the normative description. The hub's tests POST `examples/ingest-request.json`
and compare the reply byte-for-byte against `examples/ingest-response.json`, then post it a
second time and compare against `examples/ingest-response-duplicate.json`. GATBOX's tests
build a payload from its own report JSON and compare it against the same request example.

`examples/roster-response.json` and `examples/orders-response.json` are illustrative: the tests
assert their keys and types rather than exact bytes, because their content depends on what is
on the floor.

## Endpoints

All paths are relative to the hub's base URL. Every response is
`application/json; charset=utf-8`.

| method | path | auth |
|---|---|---|
| GET | `/api/v1/health` | none |
| POST | `/api/v1/ingest` | device token |
| GET | `/api/v1/roster` | device token |
| GET | `/api/v1/machines/<slug>/orders?status=open` | device token |

### Errors

Always `{"error": "<message>"}` with a meaningful status. `400` malformed or over a limit,
`401` bad or missing token, `404` unknown path or machine, `405` wrong method, `413` body too
large, `415` wrong content type, `429` rate limited, `500` unhandled.

An error status means **nothing was written**. Ingest is all-or-nothing at the request level;
per-item outcomes only appear in a `200`.

## Authentication

```
Authorization: Bearer gbx_<public_id>.<secret>
```

`public_id` is 12 lowercase hex characters; `secret` is 43 characters of URL-safe base64. The
hub stores only a hash of the secret, so the public id is what it looks the device up by. A
token is shown once, when `scripts/create_device.py` mints it.

`GET /api/v1/health` takes no token on purpose: GATBOX uses it to decide whether the LAN
address or the tunnel is reachable, which it needs to know before it commits to a request.

## Identity and idempotency

Every item carries a `uid` that GATBOX computes. Re-sending an item is harmless: the hub
reports `duplicate` and changes nothing. The uid rules are **part of the contract**:

```
rail_session  sha256(f"{public_id}|rail_session|{file}").hexdigest()[:32]
reading       sha256(f"{public_id}|reading|{file}|{epoch:.3f}").hexdigest()[:32]
order         uuid4().hex                 — an order has no natural key
```

`file` is the CSV's base name, e.g. `rail_20260925_021402.csv`. It is the only identity a
session has on the Pi, and it is local wall-clock time with no zone, so it is not unique
across devices — scoping the hash by `public_id` is what makes it so.

**`{epoch:.3f}` is exact.** Three decimals, always, even for a whole number. Formatting the
same reading as `.6f` would produce a different uid and silently duplicate a trace. At ~2
samples per second, milliseconds are unambiguous.

### Only completed sessions may be sent

A session is complete when its file is no longer the live one (not named by
`/run/gatbox/current`). This is not a preference. The trace is downsampled, and a partial
session buckets differently from the finished one, so the same reading would hash to a
different uid in each — the duplicate check would miss and the trace would be stored twice.

## Time

`epoch` — a float of UTC seconds — is authoritative everywhere. The CSV's `iso_time` column is
local wall clock with no offset and is never sent.

Each session also carries `clock`, because the Pi knows when it cannot be trusted:

| `clock.source` | meaning |
|---|---|
| `ntp` | synchronised at session start; absolute times are good |
| `rtc` | from the battery-backed clock, last set from NTP at `clock.ntp_from` |
| `unverified` | no NTP had been seen; **absolute times may be wrong** |

Readings carry `up` (the Pi's monotonic uptime in seconds) alongside `epoch`. Within a session,
`up` is correct even when the wall clock is not, so it is what relative timing should use.

## Limits

| | |
|---|---|
| items per request | 100 |
| readings per session | 2000 |
| readings per request | 20000 |
| request body | 8 MB |

Exceeding any of them is a `400` and writes nothing. GATBOX decides how to batch within them.
2000 points is what `GET /api/rail/samples/<name>?max=2000` on the Pi produces: its downsampler
keeps the minimum and maximum of each bucket and never discards a `spike`, an `alarm` or an
out-of-range sample, so the shape of the trace survives.

## Item kinds

### `rail_session`

The hub stores what GATBOX computed; it does not recompute statistics. `machine` must be a
slug the hub knows — an unknown one is `rejected`, never created.

`verdict.state` is one of `held`, `left`, `over`, or `null` when the profile has no window
(bench and free profiles have no pass/fail). GATBOX is the only place this is decided.

`window`, `alarm_hi` and `powered` may be `null` together for a bench profile.

### `order`

A maintenance order raised at the bench. `rail_session` optionally links it to the session
that prompted it, by that session's uid. The hub records it with `source: "gatbox"` and the
`uid` as its `external_id`.

**Send the session before an order that names it.** An order whose `rail_session` the hub has
not seen is `rejected` rather than stored with the link quietly dropped — a link that silently
disappears is worse than a retry, and both items being idempotent makes the retry free.

Nothing on GATBOX raises one yet — the hub accepts them so that this contract does not need a
v1.1 and a re-vendoring when it does.

## Response

```json
{
  "contract": "v1",
  "received": 2,
  "results": [
    {"uid": "…", "kind": "rail_session", "status": "created",
     "readings": {"created": 3, "duplicate": 0}},
    {"uid": "…", "kind": "order", "status": "duplicate"}
  ]
}
```

`status` is `created`, `duplicate`, or `rejected` with a `reason`. Results are in the order the
items were sent. The response carries no timestamps, so it is reproducible and can be compared
against the examples exactly.
