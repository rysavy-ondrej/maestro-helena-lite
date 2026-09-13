"""Planting listed indicators into real flows, and labelling what was planted.

Mirrors `scripts/plant_indicators.py`. `docs/synthetic-corpus.md` is the design.

The properties worth testing are not that a string was replaced. They are that a
planted record is **still a record the pipeline accepts** — a plant that gets
quarantined tests nothing — and that each scenario plants the thing its label
claims, because the label is what a later assertion would be written against.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import plant_indicators as plant  # noqa: E402

from helena.normalizer import CAPTURE_SUFFIX, FlowRecord, scan_captures  # noqa: E402

BASE = 1758326439.9195


def a_flow() -> dict:
    """One TCP flow with DNS and TLS, so every scenario has something to rewrite."""
    return {
        "id": "tcp.1",
        "ts": BASE,
        "td": 0.5,
        "ip": {
            "proto": "TCP",
            "src": "10.127.0.100",
            "dst": "93.184.216.34",
            "bsent": 500,
            "brecv": 9000,
            "psent": 6,
            "precv": 9,
        },
        "tcp": {"srcport": 51000, "dstport": 443},
        # `recs` is required by the input contract, and leaving it out is how
        # this fixture was wrong on first writing: the record validated nowhere
        # and the test that caught it is the one below.
        "tls": {
            "sni": "example.com",
            "ja3": "a" * 32,
            "recs": [{"ct": 22, "len": 512, "ver": "TLS 1.2"}],
        },
        "dns": {
            "rcode": 0,
            "queries": [{"qn": "example.com", "qt": "A"}],
            "responses": [
                {"rr": "answer", "qn": "example.com", "rt": "A", "rv": "93.184.216.34",
                 "ttl": 300}
            ],
        },
    }


def an_export(**counts: int) -> dict:
    """A ThreatFox export in the `{id: [entry]}` shape the real one uses."""
    document: dict = {}
    identifier = 1
    def add(value: str, kind: str, level: int) -> None:
        nonlocal identifier
        document[str(identifier)] = [
            {
                "ioc_value": value,
                "ioc_type": kind,
                "confidence_level": level,
                "malware_printable": "Vidar",
            }
        ]
        identifier += 1
    add("203.0.113.10:8000", "ip:port", 100)
    add("evil.example.net", "domain", 100)
    add("weak.example.net", "domain", 50)
    add("198.51.100.7:9001", "ip:port", 50)
    return document


@pytest.fixture
def captures(tmp_path: Path) -> Path:
    """A capture store of five files, one plant per file."""
    directory = tmp_path / "day"
    directory.mkdir()
    for index in range(10):
        body = b"".join(
            json.dumps({**a_flow(), "ts": BASE + offset}).encode() + b"\n"
            for offset in (0.0, 1.0, 2.0)
        )
        # Named by content the way a capture is, so `scan_captures` accepts it.
        import hashlib

        digest = hashlib.sha256(body).hexdigest()
        (directory / f"{digest}{CAPTURE_SUFFIX}").write_bytes(body)
        if index == 0:
            continue
        # Vary the body so each file has its own digest.
        body = body.replace(b'"tcp.1"', f'"tcp.{index}"'.encode())
        digest = hashlib.sha256(body).hexdigest()
        (directory / f"{digest}{CAPTURE_SUFFIX}").write_bytes(body)
    return directory


@pytest.fixture
def export(tmp_path: Path) -> Path:
    path = tmp_path / "export"
    path.mkdir()
    (path / "recent.json").write_text(json.dumps(an_export()))
    return path


def plants(out: Path) -> list[dict]:
    return json.loads((out / "LABELS.json").read_text())["plants"]


def build(captures: Path, export: Path, out: Path, **kwargs) -> list[plant.Planted]:
    return plant.build(
        captures,
        export,
        out,
        scenarios=kwargs.pop("scenarios", list(plant.SCENARIOS)),
        per_scenario=kwargs.pop("per_scenario", 1),
        threshold=kwargs.pop("threshold", 0.80),
    )


def test_a_planted_record_is_still_a_record_the_pipeline_accepts(
    captures: Path, export: Path, tmp_path: Path
):
    """The property everything else depends on.

    A plant that fails the input contract is quarantined rather than enriched, so
    it would produce no claim, no context entity and nothing for an agent to
    read — a corpus that tests the quarantine path while appearing to test the
    enrichment one.
    """
    out = tmp_path / "planted"
    build(captures, export, out)
    for capture in out.glob(f"*{CAPTURE_SUFFIX}"):
        for line in capture.read_text().splitlines():
            if line.strip():
                FlowRecord.model_validate_json(line)


def test_the_output_is_a_capture_store(captures: Path, export: Path, tmp_path: Path):
    out = tmp_path / "planted"
    labels = build(captures, export, out)
    found = scan_captures(out)
    assert len(found) == len(labels)


def test_contacted_address_is_reachable_as_a_destination(
    captures: Path, export: Path, tmp_path: Path
):
    """The ordinary path: the host contacted the listed address, on the listed port."""
    out = tmp_path / "planted"
    [label] = build(captures, export, out, scenarios=["contacted-address"])
    record = next(
        item
        for item in (
            json.loads(line)
            for line in (out / label.capture).read_text().splitlines()
            if line.strip()
        )
        if item["ip"]["dst"] == "203.0.113.10"
    )
    assert record["tcp"]["dstport"] == 8000, "the listed port was not carried across"
    assert label.expects_deterministic_escalation is True


def test_resolved_only_never_becomes_a_destination(
    captures: Path, export: Path, tmp_path: Path
):
    """Scope before severity, built as data.

    The whole point of the scenario is a claim about an entity the host resolved
    and never contacted. If the generator also set `ip.dst` this would be
    `contacted-address` under another name, and the composition rule's refusal
    would never be exercised.
    """
    out = tmp_path / "planted"
    [label] = build(captures, export, out, scenarios=["resolved-only"])
    records = [
        json.loads(line)
        for line in (out / label.capture).read_text().splitlines()
        if line.strip()
    ]
    answered = [
        record
        for record in records
        if any(
            answer.get("rv") == "203.0.113.10"
            for answer in record.get("dns", {}).get("responses", [])
        )
    ]
    assert answered, "the address was not planted as a DNS answer"
    assert all(record["ip"]["dst"] != "203.0.113.10" for record in records), (
        "the address was also contacted, which makes this contacted-address"
    )
    assert label.expects_deterministic_escalation is False


def test_port_mismatch_observes_a_different_port_than_the_one_listed(
    captures: Path, export: Path, tmp_path: Path
):
    """`ADR-0042`: the port qualifies the match, it does not filter it."""
    out = tmp_path / "planted"
    [label] = build(captures, export, out, scenarios=["port-mismatch"])
    record = next(
        item
        for item in (
            json.loads(line)
            for line in (out / label.capture).read_text().splitlines()
            if line.strip()
        )
        if item["ip"]["dst"] == "203.0.113.10"
    )
    assert record["tcp"]["dstport"] == plant.MISMATCH_PORT != 8000
    assert label.expects_deterministic_escalation is None, (
        "whether a port-mismatched claim escalates is a policy question, and the "
        "label must not answer it"
    )


def test_a_weak_domain_indicator_lands_in_a_record_that_can_carry_it(
    captures: Path, export: Path, tmp_path: Path
):
    """The bug the first run found: the record has to follow the indicator's type.

    `below-threshold` takes whatever the export holds under the threshold. When
    that is a domain it needs a DNS record, and choosing the record from the
    scenario's name instead produced a `KeyError: 'dns'` on real data.
    """
    out = tmp_path / "planted"
    [label] = build(captures, export, out, scenarios=["below-threshold"])
    assert label.confidence < 0.80
    body = (out / label.capture).read_text()
    assert label.indicator in body
    assert label.expects_deterministic_escalation is False


def test_the_labels_do_not_claim_a_verdict(captures: Path, export: Path, tmp_path: Path):
    """`docs/synthetic-corpus.md` §5. The traffic is benign with a rewritten address.

    A field inviting someone to write down the verdict a model *should* produce is
    how a fixture becomes a benchmark nobody meant to publish, over traffic whose
    only malicious property is a string this script substituted.
    """
    out = tmp_path / "planted"
    build(captures, export, out)
    document = json.loads((out / "LABELS.json").read_text())
    assert "what_these_labels_are" in document
    for entry in document["plants"]:
        assert "expected_verdict" not in entry
        assert "malicious" not in {key.lower() for key in entry}


def test_an_export_with_nothing_above_the_threshold_is_refused(
    captures: Path, tmp_path: Path
):
    """Silently planting a weak indicator where a strong one was asked for would
    produce a corpus whose `contacted-address` cases never escalate, and the
    failure would read as a bug in the escalation rule."""
    weak_only = tmp_path / "weak"
    weak_only.mkdir()
    (weak_only / "recent.json").write_text(
        json.dumps({"1": [{"ioc_value": "a.example", "ioc_type": "domain",
                           "confidence_level": 10}]})
    )
    with pytest.raises(plant.PlantError, match="threshold"):
        build(captures, weak_only, tmp_path / "out")


def test_more_plants_than_captures_is_refused(captures: Path, export: Path, tmp_path: Path):
    """One plant per capture, so a context is never two scenarios at once."""
    with pytest.raises(plant.PlantError, match="cannot carry"):
        build(captures, export, tmp_path / "out", per_scenario=100)
