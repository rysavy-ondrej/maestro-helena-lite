# Capture fixtures — the `flow-envelope` format

One capture, in the **second input format**, so that "a second input format is
an adapter, not a contract change" (`concept/06-technology.md`,
`concept/07-principles.md`) is something the suite measures rather than
something a comment claims.

| Capture | Records | Bytes | What it is |
| --- | --- | --- | --- |
| `0d6634914060f34869a0258296b45cc1dc9906002184f78f3e363e320bfe2eca.jsonl` | 10 | 11 387 | The ten records of `../captures/ace6ca33….jsonl`, in `flow-envelope` |

**It is a synthetic format. Nothing sends it.** It exists to be read by a second
adapter, and every record in it is a mechanical transform of the corresponding
record of the layer-coverage capture next door — the same real records, in the
same order, with nothing added and nothing dropped:

```json
{"format":"flow-envelope","flow_id":<id>,"start":<ts>,"duration":<td>,"layers":{…}}
```

`tests/test_normalizer.py::envelope_line` is the transform, and
`test_the_envelope_fixture_is_the_flat_capture_transformed` re-derives this file
from `../captures/ace6ca33….jsonl` and compares it byte for byte — two copies of
a derivation that could drift apart are worth no more than two copies of a
version constant.

## Why it is a separate directory

A capture directory holds **one format**. A deployment reads one format, named
by `HELENA_INPUT_FORMAT`, and mixing two in a directory would make "which
adapter reads this file" a property of the file — which is exactly the sniffing
that `helena.normalizer` refuses to do.

The files are still named by their own sha256 and `scan_captures` still refuses
one whose name and content disagree: a capture's identity is the hash of the
file whatever format is inside it.
