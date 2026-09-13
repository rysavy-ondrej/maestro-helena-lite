"""Moving a capture in time: what shifts, what must not, and what is refused.

Mirrors `scripts/rebase_capture.py`. The property worth testing is not that
addition works — it is that **every absolute timestamp in a record moves by the
same amount and nothing else moves at all**, because a record whose segments
predate its own start is not something any downstream check would catch.

The day capture (`data/demo/20250920`) carries four absolute epochs and the
committed sample carries one, so a test written only against the sample would
pass while the script silently left three fields behind. These fixtures carry all
four.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import rebase_capture as rebase  # noqa: E402

from helena.normalizer import scan_captures  # noqa: E402

#: 2025-09-20T00:00:39Z, the day capture's own first record.
BASE = 1758326439.9195


def a_record(**overrides: object) -> dict:
    """One flow with all four absolute epochs and both durations."""
    record = {
        "id": "tcp.1",
        "ts": BASE,
        "td": 0.5,
        "tx": BASE + 60.0,
        "ip": {
            "proto": "TCP",
            "src": "10.127.0.100",
            "dst": "8.8.8.8",
            "bsent": 77,
            "brecv": 208,
            "psent": 1,
            "precv": 1,
        },
        "tcp": {
            "srcport": 51000,
            "dstport": 443,
            "segs": [{"ts": BASE + 0.01, "len": 100, "ct": 1}],
        },
        "dns": {"rcode": 0, "responses": [{"rr": "answer", "qn": "a.example",
                                           "rt": "A", "rv": "1.2.3.4", "ttl": 3381}]},
    }
    record.update(overrides)
    return record


@pytest.fixture
def source(tmp_path: Path) -> Path:
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "capture_a.jsonl").write_bytes(
        b"".join(
            json.dumps(a_record(ts=BASE + offset)).encode() + b"\n"
            for offset in (0.0, 1.5, 3.0)
        )
    )
    return directory


def records_in(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def only_capture(out: Path) -> list[dict]:
    written = [child for child in out.iterdir() if child.suffix == ".jsonl"]
    assert len(written) == 1, f"expected one capture, found {written}"
    return records_in(written[0])


def test_every_absolute_epoch_moves_by_the_same_delta(source: Path, tmp_path: Path):
    """The one property. Four fields, one delta, and the durations untouched."""
    out = tmp_path / "out"
    rebase.rebase(source, out, delta=1000.0)
    before, after = records_in(source / "capture_a.jsonl"), only_capture(out)
    assert len(before) == len(after)
    for was, now in zip(before, after, strict=True):
        assert now["ts"] == pytest.approx(was["ts"] + 1000.0)
        assert now["tx"] == pytest.approx(was["tx"] + 1000.0)
        assert now["tcp"]["segs"][0]["ts"] == pytest.approx(
            was["tcp"]["segs"][0]["ts"] + 1000.0
        )


def test_a_duration_is_not_a_time_and_does_not_move(source: Path, tmp_path: Path):
    """`td` and a DNS `ttl` are spans, not instants. Shifting one is a corruption."""
    out = tmp_path / "out"
    rebase.rebase(source, out, delta=86_400.0)
    for was, now in zip(
        records_in(source / "capture_a.jsonl"), only_capture(out), strict=True
    ):
        assert now["td"] == was["td"]
        assert now["dns"]["responses"][0]["ttl"] == was["dns"]["responses"][0]["ttl"]


def test_relative_spacing_survives(source: Path, tmp_path: Path):
    """A capture is traffic, and traffic is the intervals between its records."""
    out = tmp_path / "out"
    rebase.rebase(source, out, delta=-5_000.0)
    before = [record["ts"] for record in records_in(source / "capture_a.jsonl")]
    after = [record["ts"] for record in only_capture(out)]
    gaps_before = [b - a for a, b in zip(before, before[1:])]
    gaps_after = [b - a for a, b in zip(after, after[1:])]
    assert gaps_after == pytest.approx(gaps_before)


def test_an_undeclared_timestamp_is_refused_and_named(tmp_path: Path):
    """The safety net, and the reason the script can be trusted on a new producer.

    A fifth epoch that nothing moves would leave a record disagreeing with itself
    about when it happened, and no downstream check looks for that. So an
    epoch-shaped number this script does not recognise is a refusal naming the
    path, not a field quietly left behind.
    """
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "capture.jsonl").write_bytes(
        json.dumps(a_record(first_seen=BASE - 400.0)).encode() + b"\n"
    )
    with pytest.raises(rebase.RebaseError) as refused:
        rebase.span(rebase.sources(directory))
    assert "/first_seen" in str(refused.value)


def test_a_record_without_a_usable_ts_is_refused(tmp_path: Path):
    """Every record is windowed on `ts`; one without it cannot be binned at all."""
    directory = tmp_path / "source"
    directory.mkdir()
    record = a_record()
    record["ts"] = "2025-09-20T00:00:39Z"
    (directory / "capture.jsonl").write_bytes(json.dumps(record).encode() + b"\n")
    with pytest.raises(rebase.RebaseError, match="ts="):
        rebase.span(rebase.sources(directory))


def test_the_output_is_a_capture_store_the_shipped_reader_accepts(
    source: Path, tmp_path: Path
):
    """`<sha256>.jsonl`, so `replay_capture.py` and `scan_captures` take it as is."""
    out = tmp_path / "out"
    rebase.rebase(source, out, delta=10.0)
    found = scan_captures(out)
    assert len(found) == 1
    assert sum(capture.record_count for capture in found.values()) == 3


def test_the_manifest_says_it_was_rebased(source: Path, tmp_path: Path):
    """A rebased capture that does not say so is a lie by omission.

    Nothing reading the directory later could otherwise tell moved traffic from
    traffic that happened then, and that difference is the whole reason
    `docs/evaluation-corpus.md` requires enrichment to be contemporaneous.
    """
    out = tmp_path / "out"
    summary = rebase.rebase(source, out, delta=1234.0)
    written = rebase.manifest(summary, source, out)
    assert written["kind"] == "rebased-capture"
    assert written["delta_seconds"] == 1234.0
    assert "not_an_evaluation_corpus" in written
    assert written["source_span_utc"][0].startswith("2025-09-20")


def test_nothing_is_written_when_a_record_is_refused(tmp_path: Path):
    """The scan is a whole pass before the first byte is written.

    A directory half full of rebased captures beside a refusal is worse than no
    output: the next run cannot tell which files are the new ones.
    """
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "a.jsonl").write_bytes(json.dumps(a_record()).encode() + b"\n")
    (directory / "b.jsonl").write_bytes(
        json.dumps(a_record(first_seen=BASE)).encode() + b"\n"
    )
    out = tmp_path / "out"
    with pytest.raises(rebase.RebaseError):
        rebase.rebase(directory, out, delta=1.0)
    assert not out.exists() or not list(out.glob("*.jsonl"))


def test_ending_now_puts_the_whole_capture_in_the_past(source: Path):
    """The default an operator wants: a window that has closed can be assessed.

    A capture rebased to START now spans into the future, and a window that has
    not happened yet never closes, so the contexts never complete.
    """
    first, last, _ = rebase.span(rebase.sources(source))
    delta = datetime.now(timezone.utc).timestamp() - last
    assert first + delta < datetime.now(timezone.utc).timestamp()
