#!/usr/bin/env python3
"""Rewrite the destination of real flows to listed indicators, and label what was done.

    uv run scripts/plant_indicators.py --captures .corpus/day --export data/enrichment/threatfox \
        --out .corpus/planted --per-scenario 2
    uv run scripts/plant_indicators.py --captures .corpus/day --export data/enrichment/threatfox \
        --out .corpus/planted --scenario contacted-address --scenario resolved-only

`docs/synthetic-corpus.md` is the design, the scenario table and — the part worth
reading before using the output — §5, what this corpus cannot measure.

## Why it exists

Ordinary traffic matches nothing: `demo/assess_a_slice.py` pass A against the real
feed is 131 entities and every one is `no_match`. Since the pre-triage gate
(`docs/decisions/0047-the-pre-triage-gate.md`) a context with no claims never
reaches a model at all, so on a corpus of real traffic **the agents are
unreachable**. Some traffic has to intersect the feed for triage, the analyst and
the escalation path to run at all.

## What it does and does not touch

A planted record is a **real flow with its destination rewritten**. The byte and
packet counts, the duration, the TLS parameters and the timing are what the
sensor observed, because the composition rule reads those statistics and a
generator inventing them would be testing its author's imagination.

`ip.src` is never rewritten, and the tenant and sensor are not in a record at all
— the normalizer stamps them from configuration. A generator able to write an
identity would be writing the one field `concept/instruction.md` §6 says must
never silently default.

Maturity: `experimental`. Exercised by `tests/test_plant.py`.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena.normalizer import CAPTURE_SUFFIX, describe_capture  # noqa: E402

#: The five scenarios, each turning a different rule on or off so that a failure
#: names which. `docs/synthetic-corpus.md` §3 is the table.
SCENARIOS = (
    "contacted-address",
    "resolved-only",
    "port-mismatch",
    "queried-domain",
    "below-threshold",
)

#: A port no listed `ip:port` in the snapshot is likely to name, used by
#: `port-mismatch` so the observed port and the claimed one differ on purpose.
MISMATCH_PORT = 8443


class PlantError(RuntimeError):
    """An input this script refuses, naming what and why."""


@dataclass(frozen=True)
class Indicator:
    """One listed indicator, as the feed publishes it."""

    value: str
    ioc_type: str
    confidence: float
    malware: str | None

    @property
    def address(self) -> tuple[str, int | None]:
        """`ip:port` split into its two halves, which is how the feed lists it.

        `concept/instruction.md` §6 lists an `ip:port` joined against bare
        addresses as a recurring trap; the port is a separate fact that qualifies
        the match, so it is split here rather than carried as one string.
        """
        if ":" not in self.value:
            return self.value, None
        host, _, port = self.value.rpartition(":")
        return host, int(port) if port.isdigit() else None


def indicators(export: Path) -> list[Indicator]:
    """Every indicator in a ThreatFox export file or directory of them."""
    files = sorted(export.glob("*.json")) if export.is_dir() else [export]
    if not files:
        raise PlantError(f"{export} holds no .json export")
    found: list[Indicator] = []
    for path in files:
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as bad:
            raise PlantError(f"{path} is not a readable JSON export: {bad}") from bad
        if not isinstance(document, dict):
            raise PlantError(f"{path} is not the `{{id: [entry]}}` export shape")
        for entries in document.values():
            for entry in entries if isinstance(entries, list) else []:
                value, kind = entry.get("ioc_value"), entry.get("ioc_type")
                if not value or not kind:
                    continue
                level = entry.get("confidence_level")
                found.append(
                    Indicator(
                        value=value,
                        ioc_type=kind,
                        # The feed's 0-100 scale, divided the way
                        # `sql/migrations/0014_feed_mapping_views.sql` divides it.
                        confidence=(float(level) / 100.0) if level is not None else 0.0,
                        malware=entry.get("malware_printable"),
                    )
                )
    if not found:
        raise PlantError(f"{export} yielded no indicator")
    return found


def records_of(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text().splitlines() if line.strip()
    ]


def pick(records: list[dict[str, Any]], *, needs: str) -> int | None:
    """The index of a record this scenario can be built from, or `None`.

    Returns an index rather than the record because the caller rewrites in place
    in a copy of the file, and a scenario has to be able to say *which* record it
    planted into for the label to be checkable.
    """
    for index, record in enumerate(records):
        if needs == "tcp" and isinstance(record.get("tcp"), dict):
            return index
        if needs == "dns":
            dns = record.get("dns")
            if isinstance(dns, dict) and dns.get("queries") and dns.get("responses"):
                return index
    return None


def plant_address(
    record: dict[str, Any], indicator: Indicator, *, port: int | None
) -> dict[str, Any]:
    """The flow, contacted to a listed address. `port=None` leaves the observed one."""
    planted = json.loads(json.dumps(record))
    host, listed_port = indicator.address
    planted["ip"]["dst"] = host
    if port is not None:
        planted["tcp"]["dstport"] = port
    elif listed_port is not None:
        planted["tcp"]["dstport"] = listed_port
    return planted


def plant_resolved_only(record: dict[str, Any], indicator: Indicator) -> dict[str, Any]:
    """The address as a DNS answer and nowhere else.

    `ip.dst` is deliberately left as it was: the point of this scenario is a claim
    about an entity the host **resolved and never contacted**, which the
    composition rule must refuse to escalate on. An implementation that also set
    `ip.dst` would be testing `contacted-address` twice.
    """
    planted = json.loads(json.dumps(record))
    host, _ = indicator.address
    answers = planted["dns"]["responses"]
    answers[0] = {**answers[0], "rr": "answer", "rt": "A", "rv": host}
    return planted


def plant_domain(record: dict[str, Any], indicator: Indicator) -> dict[str, Any]:
    """The domain queried, answered and offered as the TLS server name."""
    planted = json.loads(json.dumps(record))
    dns = planted["dns"]
    dns["queries"] = [{**dns["queries"][0], "qn": indicator.value}]
    dns["responses"] = [{**dns["responses"][0], "qn": indicator.value}]
    if isinstance(planted.get("tls"), dict):
        planted["tls"]["sni"] = indicator.value
    return planted


def _for(
    scenario: str,
    repeat: int,
    addresses: list[Indicator],
    domains: list[Indicator],
    weak: list[Indicator],
    threshold: float,
) -> Indicator:
    """Which indicator a scenario plants on its `repeat`-th pass.

    Separate from the planting because the record a scenario needs depends on the
    indicator's TYPE: `below-threshold` takes whatever is under the threshold,
    and whether that is an address or a domain decides which record can carry it.
    """
    if scenario == "below-threshold":
        if not weak:
            raise PlantError(
                f"no indicator below the configured threshold {threshold}; "
                f"'below-threshold' cannot be built from this export"
            )
        return weak[repeat % len(weak)]
    if scenario == "queried-domain":
        return domains[repeat % len(domains)]
    if scenario in {"contacted-address", "port-mismatch", "resolved-only"}:
        return addresses[repeat % len(addresses)]
    raise PlantError(f"{scenario!r} is not one of {list(SCENARIOS)}")


@dataclass
class Planted:
    """One plant, for the label file."""

    scenario: str
    capture: str
    record_id: str
    host: str
    indicator: str
    ioc_type: str
    confidence: float
    malware: str | None
    expects_claim: bool
    expects_deterministic_escalation: bool | None


def write_labels(
    out: Path, labels: list[Planted], *, captures: Path, export: Path, threshold: float
) -> dict[str, Any]:
    """`LABELS.json` beside the captures. Written by `build`, never by the CLI.

    A planted corpus without its labels is a directory of traffic that looks like
    an intrusion and says nothing about why, so producing one without the other
    is not an option this module offers.
    """
    document = {
        "kind": "planted-capture",
        "written_by": "scripts/plant_indicators.py",
        "captures": str(captures),
        "export": str(export),
        "threshold": threshold,
        "plants": [label.__dict__ for label in labels],
        "what_these_labels_are": (
            "Expectations about the DETERMINISTIC layer -- the join, the "
            "composition rule and the configured threshold -- and nothing else. "
            "The traffic is a real benign flow with a rewritten destination, so "
            "no entry says what a verdict should be. See docs/synthetic-corpus.md "
            "section 5."
        ),
    }
    (out / "LABELS.json").write_text(json.dumps(document, indent=2) + "\n")
    return document


def build(
    captures: Path,
    export: Path,
    out: Path,
    *,
    scenarios: Iterable[str],
    per_scenario: int,
    threshold: float,
) -> list[Planted]:
    """Plant into copies of the captures, write them and their labels, return them."""
    sources = sorted(captures.glob(f"*{CAPTURE_SUFFIX}"))
    if not sources:
        raise PlantError(
            f"{captures} holds no capture. It must be a capture store — files "
            f"named <sha256>{CAPTURE_SUFFIX}, which scripts/rebase_capture.py writes."
        )
    pool = indicators(export)
    addresses = [i for i in pool if i.ioc_type == "ip:port" and i.confidence >= threshold]
    domains = [i for i in pool if i.ioc_type == "domain" and i.confidence >= threshold]
    weak = [i for i in pool if 0.0 < i.confidence < threshold]
    if not addresses or not domains:
        raise PlantError(
            f"the export has {len(addresses)} ip:port and {len(domains)} domain "
            f"indicator(s) at or above the configured threshold {threshold}; "
            f"this generator needs at least one of each"
        )

    out.mkdir(parents=True, exist_ok=True)
    labels: list[Planted] = []
    taken = 0
    for scenario in scenarios:
        for repeat in range(per_scenario):
            if taken >= len(sources):
                raise PlantError(
                    f"{len(sources)} capture(s) cannot carry {taken + 1} plants: "
                    f"one plant per capture, so that a context is never two "
                    f"scenarios at once and a failing label names one rule"
                )
            source = sources[taken]
            taken += 1
            records = records_of(source)
            # The indicator is chosen BEFORE the record, because which record a
            # scenario needs follows from the indicator's type and not from the
            # scenario's name: `below-threshold` takes whatever weak indicator
            # the export happens to hold, and a domain one needs a DNS record.
            indicator = _for(scenario, repeat, addresses, domains, weak, threshold)
            wants = "dns" if (
                scenario in {"queried-domain", "resolved-only"}
                or indicator.ioc_type == "domain"
            ) else "tcp"
            index = pick(records, needs=wants)
            if index is None:
                raise PlantError(
                    f"{source.name} holds no record with a {wants} observation, "
                    f"which {scenario!r} needs"
                )

            if scenario == "contacted-address":
                records[index] = plant_address(records[index], indicator, port=None)
                expects_escalation = True
            elif scenario == "port-mismatch":
                records[index] = plant_address(
                    records[index], indicator, port=MISMATCH_PORT
                )
                # The port qualifies the match rather than filtering it
                # (ADR-0042), so whether this escalates is a policy question the
                # label does not pretend to answer.
                expects_escalation = None
            elif scenario == "resolved-only":
                records[index] = plant_resolved_only(records[index], indicator)
                expects_escalation = False
            elif scenario == "queried-domain":
                records[index] = plant_domain(records[index], indicator)
                expects_escalation = None
            elif scenario == "below-threshold":
                if indicator.ioc_type == "domain":
                    records[index] = plant_domain(records[index], indicator)
                else:
                    records[index] = plant_address(records[index], indicator, port=None)
                expects_escalation = False
            else:
                raise PlantError(f"{scenario!r} is not one of {list(SCENARIOS)}")

            staged = out / f".{source.name}.staging"
            staged.write_bytes(
                b"".join(
                    json.dumps(record, separators=(",", ":")).encode() + b"\n"
                    for record in records
                )
            )
            described = describe_capture(staged)
            final = out / f"{described.sha256}{CAPTURE_SUFFIX}"
            staged.replace(final)
            labels.append(
                Planted(
                    scenario=scenario,
                    capture=final.name,
                    record_id=str(records[index].get("id")),
                    host=records[index]["ip"]["src"],
                    indicator=indicator.value,
                    ioc_type=indicator.ioc_type,
                    confidence=indicator.confidence,
                    malware=indicator.malware,
                    expects_claim=True,
                    expects_deterministic_escalation=expects_escalation,
                )
            )
    write_labels(out, labels, captures=captures, export=export, threshold=threshold)
    return labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--captures", required=True, type=Path)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--per-scenario", type=int, default=1)
    parser.add_argument(
        "--scenario", action="append", choices=SCENARIOS, dest="scenarios"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="override the configured escalation threshold (default: read policy)",
    )
    arguments = parser.parse_args(argv)

    threshold = arguments.threshold
    if threshold is None:
        from helena import policy  # noqa: PLC0415 — one call, at the edge

        loaded = policy.thresholds()
        threshold = loaded.for_source("threatfox")

    try:
        labels = build(
            arguments.captures,
            arguments.export,
            arguments.out,
            scenarios=arguments.scenarios or list(SCENARIOS),
            per_scenario=arguments.per_scenario,
            threshold=threshold,
        )
    except PlantError as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return 2

    print(f"{len(labels)} plant(s) into {len(labels)} capture(s) in {arguments.out}")
    for label in labels:
        expectation = {
            True: "should escalate",
            False: "should NOT escalate",
            None: "escalation is a policy question",
        }[label.expects_deterministic_escalation]
        print(
            f"  {label.scenario:<18} {label.ioc_type:<8} "
            f"{label.indicator[:34]:<34} conf {label.confidence:.2f}  {expectation}"
        )
    print(f"\n  labels in {arguments.out / 'LABELS.json'}")
    print("  These label the deterministic layer, not verdict quality —")
    print("  docs/synthetic-corpus.md §5 is what this corpus cannot measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
