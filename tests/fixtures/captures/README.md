# Capture fixtures

A **capture** is a retained file of flow records identified by the hash of the
file (`concept/02-concepts-and-taxonomy.md`), so each file here is named by its
own sha256 and `helena.normalizer.scan_captures` refuses one whose name and
content disagree. The names are opaque on purpose — an editable name would be a
second, softer identity — so this file says what each digest holds.

These captures are in the `flow-json` format — one flat JSON object per line,
the record exactly as a producer supplies it. The second format's fixture is in
`../captures-flow-envelope/`, in its own directory because a capture directory
holds one format.

Every record is a byte-for-byte copy of a line of `data/ingest/flow-sample.jsonl`
(sha256 `6c2f903e…`, cleared for the repository, datasheet in
`data/ingest/README.md`). Nothing here is synthesised: a hand-written flow record
would be a guess about the input contract, and the contract is exactly what these
fixtures exist to test.

| Capture | Records | Bytes | What it is for |
| --- | --- | --- | --- |
| `ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318.jsonl` | 10 | 10 897 | Every layer combination the sample contains, plus the edge cases below |
| `6e361f1b99b88a8b3e77aeec4b630abff5e71396087a485eea03db3bb1856e64.jsonl` | 1 | 206 | A one-record capture, whose single record is also in the capture above |

## `ace6ca33…` — the layer-coverage capture

All six layer combinations observed in the sample, in file order:

| Offset | Record | Layers | Why it is here |
| --- | --- | --- | --- |
| 0 | `udp.0` | `dns` | A CNAME → CNAME → A chain: the resolved address is at index 2, not 0 |
| 1 | `tcp.0` | `tls` + `http2` | The common HTTPS shape |
| 2 | `tcp.1` | `http` | Plaintext HTTP on port 80, no `content_type` on the request, no `server` on the response |
| 3 | `udp.4` | `dns` | The 12-record answer chain — the largest in the sample |
| 4 | `tcp.3` | `tls` + `http` | An HTTP/1 request that *does* carry `content_type` and `content_len` |
| 5 | `tcp.4` | `http` | An HTTP/1 response that carries `server` |
| 6 | `udp.7` | `dns` | `rcode` 3 — NXDOMAIN, a reverse lookup that resolved nothing |
| 7 | `tcp.24` | `tls` + `http` | **`tls.alpn == []`** — TLS observed, no protocol negotiated. Observed-but-empty, not absent |
| 8 | `udp.28` | none | **No application layer at all** — SSDP to `239.255.255.250`. `dns`, `tls`, `http` and `http2` are all null |
| 9 | `tcp.30` | `tls` | The only sampled TLS observation with a non-empty `csvers` (3 entries) beside an empty `ssvers` |

Offsets 7, 8 and 9 together are the *absence is not emptiness* invariant in real
data: a null layer, an empty array inside an observed layer, and a populated
array beside an empty one on the same observation.

## `6e361f1b…` — the one-record capture

Offset 0 is `udp.28`, the same record as offset 8 of the capture above. Two
captures sharing a record have different hashes, which is what "a capture is
identified by the hash of the *file*" means: capture identity is not derived from
the records, and the same record can belong to more than one capture.

## The assumption underneath all of this

A hash identifies a capture **only once the file closes**. These files are
closed, so their identity is settled; under live ingestion an open file has no
final digest, and capture identity — and every event id derived from it — is
provisional. `concept/08-open-questions.md` carries the assumption,
`docs/decisions/0010-capture-identity.md` records what rests on it, and
`tests/test_normalizer.py` demonstrates it by appending a record and watching the
hash change.
