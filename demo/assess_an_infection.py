#!/usr/bin/env python3
"""A real infected host, its real C2 chain, and what the pipeline makes of it.

    demo/run-demo 9
    uv run demo/assess_an_infection.py
    uv run demo/assess_an_infection.py --exercise 2026-08-09
    uv run demo/assess_an_infection.py --windows 1 --show-prompt
    uv run demo/assess_an_infection.py --out /tmp/a-run

Every other demo here runs either benign traffic or traffic this repository
rewrote. This one runs **a real malware infection**: one
[Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)
exercise from `data/connections/malware-traffic/`, a single Windows-AD client
that was actually compromised, with its actual C2 chain in the DNS queries and
TLS SNI.

The default is `2026-09-11`, *"Kongtuke Rebuke!"*: 320 connections over 21
minutes from `10.9.11.135`, whose infection chain reaches `winrun2915.com`,
`logincrypt8338.com`, `opscast3707.net` and `know.mom-nower.com`.

## The two things this demo changes, and it says so every run

**1. The timestamps are moved.** A snapshot's validity interval begins when it
was fetched, so a capture from days ago is covered by no snapshot fetchable
today and would produce no enrichment at all
(`docs/evaluation-corpus.md` §4). The records are re-stamped so the capture
*ends now*, which is `scripts/rebase_capture.py`'s operation and is permitted:
`ts` is a field of the input contract.

**2. The feed is told about the C2 domains, because it does not know them.**
Measured 2026-09-14: the **current ThreatFox export shares nothing** with any of
the ten exercises — not one address, not one domain, including the exercise
captured three days earlier. So the chain is added to the snapshot the demo
loads, and every screen that shows a match says `ADDED`.

That second point is the demo's most useful result and it is a negative one.
This is not a pipeline failure and not a feed failure: the recent export is a
rolling two-day sighting window of a few thousand indicators, and a specific
intrusion is simply not in it. **A pipeline that only knows what a feed lists
would have said `normal` about a live infection**, which is what
`docs/hazards.md` §6 and §11 are about, now measured against real malware
traffic rather than against benign browsing.

## What is real here

The connections, the hosts, the DNS chain, the TLS parameters, the byte and
packet counts, and the order and timing of the infection. The host really did
contact those domains, in that sequence.

## What a run leaves behind, and why

Five columns on a terminal cannot hold a context, and a model call summarised as
*"reached analyst"* is the outcome with everything that produced it left out. So
every run writes itself down under `.demo/assess_an_infection/` (`--out` moves
it), as YAML:

- **one file per computed context** — every entity with one enrichment record
  *per source whose declared types cover it*, so `no_match`, `missing`, `stale`
  and `failed` are four rows rather than one absence; every claim the context
  holds with the traffic of the entity it is about beside it; and every
  candidate the rules considered, including the ones that did **not** escalate
  and the rule that held each back;
- **one file per assessed window** — the request entire, the messages that went
  on the wire per attempt, the model parameters, the answer *as text* before
  validation parsed it into a verdict, the disclosure ledger, and the structured
  log lines the run emitted. A retried attempt carries a third turn quoting the
  validation error the previous answer failed on, and this is the only place
  that turn is visible: `helena.agents.assess` builds it and never returns it;
- **`run.yaml`** — the capture, the shift, the snapshot, the planted chain, the
  models, the budgets and the thresholds this run actually ran under.

Step 6 prints the same material as it happens, bounded: what is being sent, to
which endpoint under which parameters, that it is waiting, how long it waited,
what came back verbatim, and what the routing made of it.

## What it does not show

**Nothing about verdict quality.** There is no labelled corpus and there is no
answer key in this tree — the exercise's answer pages stay upstream — so what a
model says here is not scored against anything. **Not detection either**: the
match happens because the demo told the feed what to look for.

Maturity: experimental — a demonstration, not a tested component. The stages it
drives are covered by `tests/test_end_to_end.py`; this script is exercised by
running it.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from _common import (  # noqa: E402
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    RESET,
    THREATFOX_EXPORT_URL,
    YELLOW,
    banner,
    ingest,
    live_contexts,
    load_feed,
    load_suffixes,
    note,
    rule,
    schema,
    settings_for,
    stage,
    utc,
)

from helena import (  # noqa: E402
    agents,
    analyst,
    budgets,
    disclosure,
    enrichment,
    hosts,
    observability,
    orchestration,
    policy,
    rendering,
    sink,
    triage,
)
from helena.agents import ModelClient  # noqa: E402
from helena.contracts.v1 import (  # noqa: E402
    CONTRACT_VERSION,
    SCHEDULED_TRIAGE,
    AgentRequest,
    AgentResult,
    RequestVersions,
)
from helena.observability import Redactor  # noqa: E402
from helena.policy import v1 as policy_v1  # noqa: E402
from helena.rendering import v1 as rendering_v1  # noqa: E402
from helena.taxonomy import TRIAGE  # noqa: E402

CORPUS = ROOT.parent / "data" / "connections" / "malware-traffic"
DEFAULT_EXERCISE = "2026-09-11"

#: Where a run writes itself down unless `--out` says otherwise. Dot-prefixed
#: and gitignored beside `.corpus/` and `.backups/`, for `.corpus/`'s reason:
#: what lands here is derived from a capture this project holds no
#: redistribution clearance for, and a file listing real C2 infrastructure in
#: source control is a file that looks like evidence of an intrusion.
OUTPUT = ROOT.parent / ".demo" / "assess_an_infection"

#: How much of a prompt the terminal shows before it is the file's job.
#: `--show-prompt` prints them whole; the files always hold them whole.
PREVIEW = 900

#: How much of an answer the terminal shows. Larger than `PREVIEW`, because the
#: answer is what the run was for -- a triage verdict is one short JSON object,
#: and an analyst narrative is bounded by the contract at 4 000 characters.
ANSWER = 2400

#: The left margin of everything step 6 prints under one window's heading.
LEAD = "        "

#: What each exercise's traffic really reached, by the entity type the enrichment
#: join matches on. Read off the capture's own DNS, HTTP and flows -- these are
#: things the host actually contacted, not a guess about which were malicious.
#: The upstream answer keys are not in this tree, so this is *"the chain the
#: traffic shows"* and deliberately not *"the indicators of compromise"*.
#:
#: **All three types ThreatFox covers are here on purpose.** A domain-only chain
#: is what the first version of this demo planted, and it produced five claims
#: and no deterministic escalation at all -- because the composition rule's scope
#: test does not reach domain entities (`docs/hazards.md` §5). Adding the
#: addresses and the URL the same traffic carried is what makes the enrichment
#: join, and the rules on top of it, visible as more than one outcome.
CHAINS = {
    "2026-09-11": (
        # --- domains: queried, and three of them offered as a TLS server name
        ("know.mom-nower.com", "domain"),
        ("winrun2915.com", "domain"),
        ("logincrypt8338.com", "domain"),
        ("opscast3707.net", "domain"),
        ("aatthews.cfd", "domain"),
        # --- an address on its own infrastructure. The host sent it 4.77 MB
        # over 73 flows of plain HTTP and got 107 KB back: contacted, heavily,
        # both ways, on the port the indicator names.
        ("86.106.87.134:80", "ip:port"),
        # --- an address behind a CDN, reached for winrun2915.com. Contacted
        # just as really, and the rules should treat it differently: one
        # address shared by everything is not evidence about this host.
        ("104.21.91.138:443", "ip:port"),
        # --- a URL the host actually requested, from the same C2
        (
            "http://know.mom-nower.com/zgzly/e2fkf6&"
            "4a0fd955c05d43841a9a8d921ceec63b0dc5b431a9fb54b33ad7848707bc16e9/o3m8xrq0rab",
            "url",
        ),
    ),
}


def records_of(exercise: str) -> list[dict]:
    path = CORPUS / "conn" / f"{exercise}.jsonl"
    if not path.exists():
        raise SystemExit(
            f"{path} is not here. The malware corpus is not committed -- it is "
            f"records derived from third-party captures and this project holds "
            f"no redistribution clearance for them. "
            f"{CORPUS / 'README.md'} says where it comes from."
        )
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def infected_host(records: list[dict]) -> str:
    """The client the exercise is about: the one that did the talking.

    Each exercise is one LAN segment with exactly one infected client
    (`UPSTREAM-AGENTS.md`), and it is the overwhelming majority of the traffic --
    316 of 320 records in the default exercise. Derived rather than configured,
    so pointing this at another exercise needs no table entry.
    """
    counts: dict[str, int] = {}
    for record in records:
        counts[record["ip"]["src"]] = counts.get(record["ip"]["src"], 0) + 1
    return max(counts, key=counts.get)


def listed(export: bytes, chain: tuple[tuple[str, str], ...]) -> bytes:
    """The live export with the chain added, as entries the loader will map.

    Added rather than substituted: everything ThreatFox really published is still
    there, so the `no_match` rows in the output are real answers about real
    indicators and only the chain is this demo's doing.

    `ioc_type` is carried per entry rather than assumed, because the whole point
    of planting three types is that the join and the rules treat them
    differently -- an `ip:port` is split into address and port by
    `sql/migrations/0014_feed_mapping_views.sql`, and the port then qualifies
    the match instead of filtering it.
    """
    document = json.loads(export)
    base = max((int(key) for key in document if key.isdigit()), default=0) + 1
    for offset, (value, kind) in enumerate(chain):
        document[str(base + offset)] = [
            {
                "ioc_value": value,
                "ioc_type": kind,
                "threat_type": "botnet_cc",
                "malware": "win.unknown",
                "malware_alias": None,
                "malware_printable": "Unknown",
                "first_seen_utc": "2026-09-11 20:05:55",
                "last_seen_utc": None,
                # Above `config/policy.toml`'s threshold on purpose: what this
                # demo is about is the path a match takes, not the threshold,
                # which `demo/escalation_and_scope.py` varies instead.
                "confidence_level": 100,
                "is_compromised": False,
                "reference": "demo/assess_an_infection.py -- ADDED, not published",
                "tags": "demo-added",
                "anonymous": 0,
                "reporter": "demo",
            }
        ]
    return json.dumps(document).encode()


def overlap(export: bytes, records: list[dict]) -> set[str]:
    """What the capture and the REAL export already share, before anything is added."""
    document = json.loads(export)
    addresses, domains = set(), set()
    for entries in document.values():
        for entry in entries:
            value, kind = entry.get("ioc_value"), entry.get("ioc_type")
            if kind == "ip:port":
                addresses.add(value.rsplit(":", 1)[0])
            elif kind == "domain":
                domains.add(value)
    found = set()
    for record in records:
        if record["ip"]["dst"] in addresses:
            found.add(record["ip"]["dst"])
        for query in (record.get("dns") or {}).get("queries") or []:
            if query.get("qn") in domains:
                found.add(query["qn"])
        name = (record.get("tls") or {}).get("sni")
        if name in domains:
            found.add(name)
    return found


def staged(records: list[dict], directory: Path):
    """The records as a capture file, addressed by its own sha256.

    Written as they stand, spacing intact — a capture is traffic and traffic is
    the intervals between its records.
    """
    from helena.normalizer import CAPTURE_SUFFIX, describe_capture

    path = directory / "capture.jsonl"
    path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records))
    described = describe_capture(path)
    final = path.with_name(f"{described.sha256}{CAPTURE_SUFFIX}")
    path.replace(final)
    return describe_capture(final)


def request_for(projection, *, connection, settings, snapshot, normalization, budget_policy, prompt):
    """The triage request. Nothing in `src/helena` builds one — `docs/deployment.md` §1."""
    (aggregation,) = connection.execute(
        "SELECT aggregation_version FROM helena_signal_host_context_live "
        "WHERE tenant = %s AND sensor = %s AND context_id = %s",
        (projection.tenant, projection.sensor, projection.context_id),
    ).fetchone()
    return AgentRequest(
        tenant=projection.tenant,
        sensor=projection.sensor,
        emitter=TRIAGE,
        host=projection.host,
        window_start=projection.statistics.window_start,
        window_end=projection.statistics.window_end,
        context_id=projection.context_id,
        context_version=projection.context_version,
        trigger=SCHEDULED_TRIAGE,
        rendering=rendering_v1.render(
            projection, hosts.load().attributes_for(projection.host), rendering.budget()
        ),
        budgets=budget_policy.for_emitter(TRIAGE),
        versions=RequestVersions(
            prompt_version=prompt.version,
            schema_version=CONTRACT_VERSION,
            rendering_version=rendering_v1.RENDERING_VERSION,
            taxonomy_version="v1",
            enrichment_snapshot_version=snapshot,
            normalization_snapshot_version=normalization,
            policy_version=policy_v1.POLICY_VERSION,
            aggregation_version=aggregation,
            model_requested=settings.triage.model,
        ),
    )


# ---------------------------------------------------------------------------
# Writing a run down. YAML by hand, because a demo is not the place for a fifth
# dependency.
# ---------------------------------------------------------------------------
#
# `pyproject.toml` declares four runtime dependencies and none of them reads or
# writes YAML; adding one for a demo would install a package into every
# deployment that never runs it. So the emitter is here, and it is small because
# it does not have to be general: **JSON is a subset of YAML 1.2**, which makes
# `json.dumps` a correct double-quoted scalar with the standard library's
# escaping. What is written below is the block structure around that, plus the
# literal blocks that keep a prompt readable as the text it is rather than as
# one escaped line four thousand characters long.
#
# Everything written is `model_dump(mode="json")` of a contract or a policy
# model. Nothing is hand-listed, so a field added to `ContextEntity` or to
# `AgentResult` appears in these files without this demo being edited -- the
# same reason `demo/_common.py` reads the enrichment states out of the view
# rather than naming them.

#: A string a YAML reader gives back unchanged without quotes around it.
_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_.@/+-]*\Z")
#: ... except for these, which resolve to something that is not the string. A
#: plain `no` comes back as False, so `status: no` would be read as a boolean.
_RESERVED = frozenset({"true", "false", "null", "yes", "no", "on", "off", "y", "n"})


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True or value is False:
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    if _PLAIN.match(text) and text.lower() not in _RESERVED:
        return text
    return json.dumps(text)


def _literal(text: str, indent: int) -> str | None:
    """`text` as a literal block, or `None` where a quoted scalar is the safe answer.

    The chomping indicator is chosen rather than assumed. `|-` strips every
    trailing newline, so writing a prompt that ended with one under `|-` would
    produce a file whose reader gets back something the model was not sent —
    which is the whole value of the file gone for the sake of a tidier default.
    """
    if "\n" not in text or "\r" in text:
        return None
    if any(ord(character) < 32 and character != "\n" for character in text):
        return None
    if text.endswith("\n\n"):
        header, lines = "|+", text.split("\n")[:-1]
    elif text.endswith("\n"):
        header, lines = "|", text[:-1].split("\n")
    else:
        header, lines = "|-", text.split("\n")
    # A block scalar cannot express content that is nothing but empty lines: a
    # reader detects the body's indentation from the first non-empty line, and
    # with none it reads an empty string back. Rare, and a wrong round-trip is
    # not a thing to leave in a file whose whole job is being read back.
    first = next((line for line in lines if line), None)
    if first is None:
        return None
    # Detection takes its indentation from that same first non-empty line, so a
    # line beginning with a space needs the explicit indicator or the reader
    # takes the space for indentation and the content quietly loses it.
    if first[:1] in (" ", "\t"):
        header = f"{header[0]}2{header[1:]}"
    pad = " " * (indent + 2)
    return header + "\n" + "\n".join(f"{pad}{line}" if line else "" for line in lines)


def _value(value: Any, indent: int) -> str:
    if isinstance(value, str):
        block = _literal(value, indent)
        if block is not None:
            return block
    return _scalar(value)


def _pair(key: str, value: Any, indent: int, out: list[str]) -> None:
    pad = " " * indent
    if isinstance(value, dict):
        out.append(f"{pad}{key}:" if value else f"{pad}{key}: {{}}")
        for name, item in value.items():
            _pair(str(name), item, indent + 2, out)
    elif isinstance(value, (list, tuple)):
        out.append(f"{pad}{key}:" if value else f"{pad}{key}: []")
        for item in value:
            _item(item, indent + 2, out)
    else:
        out.append(f"{pad}{key}: {_value(value, indent)}")


def _item(value: Any, indent: int, out: list[str]) -> None:
    """One sequence entry. A mapping entry is written at `indent + 2` and then
    has its own leading pad replaced by `- `, which is what puts the first key on
    the dash's line without the emitter having to special-case every shape."""
    pad = " " * indent
    if isinstance(value, dict) and not value:
        out.append(f"{pad}- {{}}")
    elif isinstance(value, (list, tuple)) and not value:
        out.append(f"{pad}- []")
    elif isinstance(value, (dict, list, tuple)):
        inner: list[str] = []
        if isinstance(value, dict):
            for name, item in value.items():
                _pair(str(name), item, indent + 2, inner)
        else:
            for item in value:
                _item(item, indent + 2, inner)
        inner[0] = f"{pad}- {inner[0][indent + 2:]}"
        out.extend(inner)
    else:
        out.append(f"{pad}- {_value(value, indent)}")


def as_yaml(document: dict[str, Any]) -> str:
    out: list[str] = []
    for key, value in document.items():
        _pair(str(key), value, 0, out)
    return "\n".join(out) + "\n"


def dumped(value: Any) -> Any:
    """Whatever it is, as the JSON-shaped data the emitter takes.

    `model_dump(mode="json")` and never a hand-written dict: `Secret` serializes
    to `REDACTED` through the settings model's own serializer, so a credential
    cannot reach a file by this route, and a contract field added tomorrow is
    written without this demo knowing about it.
    """
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def write_yaml(path: Path, document: dict[str, Any], *, about: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# {about}\n"
        f"# written by demo/assess_an_infection.py; derived from a capture this\n"
        f"# project holds no redistribution clearance for -- see .gitignore\n"
        f"{as_yaml(document)}",
        encoding="utf-8",
    )
    return path


def where(path: Path) -> str:
    """The path as a reader would type it: relative to here, or absolute."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def slug(text: str) -> str:
    """`text` as one path segment. A host is an address and IPv6 carries colons."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def context_document(projection: Any, supports: Any, escalation: Any) -> dict[str, Any]:
    """One computed context, whole: what was observed, what was claimed, what the
    rules made of it.

    Three layers that this demo's terminal output can only ever summarise, and
    the distinctions between them are the ones `concept/instruction.md` §2 will
    not let anything collapse:

    | | |
    | --- | --- |
    | `entities` | every value the host touched, each carrying one enrichment record **per source whose declared types cover it** — so `no_match`, `missing`, `stale` and `failed` are four rows here and not one absence |
    | `claims` | `helena.policy.supports_in` — every claim the context holds, with the traffic of the entity it is about beside it, which is the pair the composition rule needs on one row |
    | `escalation` | what the frozen rules made of those claims, candidate by candidate, including the ones that did **not** escalate and the rule that held each back |
    """
    record = dumped(projection)
    by_type: dict[str, int] = {}
    for entity in projection.entities:
        by_type[entity.entity_type] = by_type.get(entity.entity_type, 0) + 1
    return {
        "summary": {
            "host": projection.host,
            "window_start": f"{projection.statistics.window_start:%Y-%m-%dT%H:%M:%SZ}",
            "window_end": f"{projection.statistics.window_end:%Y-%m-%dT%H:%M:%SZ}",
            "completeness": projection.statistics.completeness,
            "flows": projection.statistics.flow_count,
            "entities": len(projection.entities),
            "entities_by_type": dict(sorted(by_type.items())),
            "enrichment_records": sum(len(e.enrichment) for e in projection.entities),
            "claims": len(supports),
            "escalates": escalation.escalates,
            "escalating_evidence": list(escalation.evidence_ids),
        },
        "context": {
            key: value
            for key, value in record.items()
            if key not in ("statistics", "entities", "tls")
        },
        "statistics": record["statistics"],
        "tls": record["tls"],
        "entities": record["entities"],
        "claims": [dumped(support) for support in supports],
        "escalation": dumped(escalation),
    }


# ---------------------------------------------------------------------------
# Watching one assessment happen
# ---------------------------------------------------------------------------


@contextmanager
def waiting(label: str) -> Iterator[None]:
    """`label`, with the seconds ticking, for as long as the block runs.

    A live model call is the one part of this pipeline slow enough for a reader
    to wonder whether anything is happening at all, and ninety seconds of no
    output looks exactly like a hang. Written back over on the same line, so a
    run whose output is piped to a file keeps one line per call rather than one
    per tick.
    """
    if not sys.stdout.isatty():
        print(f"{label} …", flush=True)
        yield
        return
    stop = threading.Event()
    started = time.monotonic()

    def tick() -> None:
        while not stop.wait(0.2):
            sys.stdout.write(f"\r{label} … {time.monotonic() - started:5.1f}s")
            sys.stdout.flush()

    ticker = threading.Thread(target=tick, daemon=True)
    ticker.start()
    try:
        yield
    finally:
        stop.set()
        ticker.join(timeout=1.0)
        sys.stdout.write("\r" + " " * (len(label) + 16) + "\r")
        sys.stdout.flush()


class Watch:
    """One window's model exchanges: printed as they happen, kept for the file.

    What `orchestration.assess` gives back is an `Assessment`, and by then the
    answer has been parsed into an `AgentResult` — the text the endpoint sent is
    gone, the messages that went on the wire were never returned, and the wait
    is over. Those are the three things worth seeing on a run that costs money,
    so this holds on to them as they pass.
    """

    def __init__(self, *, show_prompt: bool) -> None:
        self.show_prompt = show_prompt
        self.exchanges: list[dict[str, Any]] = []

    def asked(self, agent: str, client: Any, messages: Any, parameters: dict) -> None:
        schema = parameters.get("schema")
        bound = len(parameters.get("tools") or ())
        self.exchanges.append(
            {
                "agent": agent,
                "attempt": parameters["attempt"],
                # `endpoint_host` and not the configured URL: userinfo, path and
                # query are dropped by the property rather than masked after the
                # fact, which is what makes it safe to write down.
                "endpoint": f"{client.endpoint_host}/{agents.COMPLETIONS_PATH}",
                "model_requested": client.model_requested,
                "parameters": {
                    "temperature": agents.TEMPERATURE,
                    "max_tokens": parameters["max_tokens"],
                    "timeout_seconds": round(parameters["timeout"], 3),
                    "response_format": None if schema is None else "json_schema",
                    "strict": None if schema is None else True,
                    "tools_bound": bound,
                },
                "messages": [
                    {"role": message.role, "characters": len(message.content),
                     "content": message.content}
                    for message in messages
                ],
                # The grammar the answer cannot leave. Large, and the reason a
                # triage call costs 122 prompt tokens instead of 694 —
                # `helena.agents.ModelClient.complete` has the measurement.
                "response_format_schema": schema,
                "status": "waiting for a response",
            }
        )
        print(f"{LEAD}{BOLD}{agent}{RESET} → POST {self.exchanges[-1]['endpoint']}"
              f"   attempt {parameters['attempt']}")
        print(f"{LEAD}  model={client.model_requested}  "
              f"temperature={agents.TEMPERATURE}  "
              f"max_tokens={parameters['max_tokens']:,}  "
              f"timeout={parameters['timeout']:.1f}s")
        print(f"{LEAD}  response_format="
              f"{'json_schema (strict)' if schema else 'none'}  tools_bound={bound}"
              f"   {DIM}one or the other, never both{RESET}")
        print(f"{LEAD}  sent {len(messages)} message(s): "
              + ", ".join(f"{m.role} {len(m.content):,} chars" for m in messages))
        for message in messages:
            self.text(f"{message.role} turn, as sent", message.content,
                      limit=None if self.show_prompt else PREVIEW)

    def answered(self, agent: str, completion: Any, elapsed: float) -> None:
        self.exchanges[-1].update(
            status="answered",
            elapsed_seconds=round(elapsed, 3),
            response={
                "model_reported": completion.model_reported,
                "prompt_tokens": completion.prompt_tokens,
                "completion_tokens": completion.completion_tokens,
                "tool_calls": [dumped(call) for call in completion.tool_calls],
                "text": completion.text,
            },
        )
        print(f"{LEAD}  {GREEN}← answered in {elapsed:.1f}s{RESET} by "
              f"{BOLD}{completion.model_reported}{RESET}   "
              f"{completion.prompt_tokens:,} prompt + "
              f"{completion.completion_tokens:,} completion tokens"
              + (f", {len(completion.tool_calls)} tool call(s)"
                 if completion.tool_calls else ""))
        self.text("the answer, exactly as it arrived", completion.text, limit=ANSWER)

    def failed(self, agent: str, error: BaseException, elapsed: float) -> None:
        self.exchanges[-1].update(
            status="failed",
            elapsed_seconds=round(elapsed, 3),
            failure={"type": type(error).__name__, "detail": str(error)},
        )
        print(f"{LEAD}  {RED}← {type(error).__name__} after {elapsed:.1f}s{RESET}: {error}")
        print(f"{LEAD}  {DIM}not a verdict: the runner retries within the bounded "
              f"policy and then returns a typed failure{RESET}")

    def text(self, label: str, text: str, *, limit: int | None) -> None:
        shown = text if limit is None else text[:limit]
        cut = len(shown) != len(text)
        print(f"{LEAD}  {DIM}┌─ {label} — {len(text):,} chars"
              f"{f', first {len(shown):,} shown' if cut else ''}{RESET}")
        for line in shown.splitlines() or ["(empty)"]:
            print(f"{LEAD}  {DIM}│{RESET} {line}")
        if cut:
            print(f"{LEAD}  {DIM}│ … the file has all of it"
                  f"{'; --show-prompt prints it here' if limit == PREVIEW else ''}{RESET}")
        print(f"{LEAD}  {DIM}└─{RESET}")


class Watched(ModelClient):
    """The configured client, with every exchange shown as it happens and kept.

    Not a mock and not a reimplementation: the call is `ModelClient.complete`,
    reached through `super()`, against the endpoint the deployment configured
    and with the payload that module builds. What is added is observation —
    which is the only way to see the messages that actually went on the wire
    (the retry feedback turn included, since that one is built inside
    `helena.agents.assess` and never leaves it) and the answer as text.

    `for_agent` is a classmethod over `cls`, so it returns one of these; the
    watch is attached afterwards rather than through the constructor, because
    the constructor is the shipped one and a demo that had to fork it would be
    demonstrating its own fork.
    """

    def observing(self, watch: Watch, *, agent: str) -> "Watched":
        self.watch, self.agent = watch, agent
        return self

    def complete(self, messages: Any, **parameters: Any) -> Any:
        self.watch.asked(self.agent, self, messages, parameters)
        started = time.monotonic()
        try:
            with waiting(f"{LEAD}  waiting for a response"):
                completion = super().complete(messages, **parameters)
        except Exception as failure:  # noqa: BLE001 — recorded, then re-raised unchanged
            self.watch.failed(self.agent, failure, time.monotonic() - started)
            raise
        self.watch.answered(self.agent, completion, time.monotonic() - started)
        return completion


def drained(log: io.StringIO) -> list[dict[str, Any]]:
    """The structured log lines written since the last drain, parsed.

    The buffer exists because every `ModelClient` builds a logger and one without
    a stream writes JSON over the top of the demo's own output. Nothing was ever
    read back out of it, which made the pipeline's own account of the run the one
    thing this demo hid — `escalation.evaluated`, `gate.evaluated`, `routed` and
    the two `agents.model.*` lines are exactly what an operator would have to
    look at, so they are shown per window and kept per window.
    """
    lines = log.getvalue().splitlines()
    log.seek(0)
    log.truncate(0)
    return [json.loads(line) for line in lines if line.strip()]


def verdict_text(outcome: Any) -> str:
    """One outcome as one line, without collapsing the three kinds into one.

    A verdict, a typed failure and a gate decision are three different terminal
    outcomes and `concept/instruction.md` §2 forbids reading any of them as
    another: a run that failed is not a run that said `normal`, and a context the
    gate cleared was never assessed by a model at all.
    """
    if isinstance(outcome, AgentResult):
        return (f"{outcome.classification}  confidence {outcome.confidence}  "
                f"{len(outcome.citations)} citation(s)  {len(outcome.gaps)} gap(s)")
    if isinstance(outcome, policy.GateDecision):
        # `reason` names why a context was NOT gated and is None exactly where it
        # was, so a cleared decision says what it is out of the two numbers that
        # decided it rather than printing that None.
        if outcome.cleared:
            return (f"cleared by the gate: {outcome.claims_read} claim(s), fewer "
                    f"than the {outcome.min_suspicious_indicators} it takes "
                    f"before a model is called")
        return f"the gate did not clear it: {outcome.reason}"
    return f"{outcome.reason}: {outcome.detail[:120]}"


def resolved_from(source: Any) -> str:
    """Which environment variable each of one agent's settings actually came from.

    `helena.config.ModelSettings.source` is what makes cross-wiring detectable
    rather than merely possible: an agent whose model came from the general
    `LLM_MODEL` and one whose came from its own override are two different
    deployments, and the difference is invisible in the resolved values.
    """
    return " ".join(
        f"{name.removeprefix('LLM_').lower()}←{variable}"
        for name, variable in source.items()
    )


def show_request(asked: Any, escalation: Any) -> None:
    """Everything about the request that is true before anything has been called."""
    versions = asked.versions
    print(f"{LEAD}context    {asked.context_id}")
    print(f"{LEAD}           at version {asked.context_version}  "
          f"{DIM}(what a citation pins){RESET}")
    print(f"{LEAD}versions   prompt {versions.prompt_version} · "
          f"schema {versions.schema_version} · "
          f"rendering {versions.rendering_version} · "
          f"taxonomy {versions.taxonomy_version} · "
          f"policy {versions.policy_version} · "
          f"aggregation {versions.aggregation_version}")
    print(f"{LEAD}snapshots  enrichment {versions.enrichment_snapshot_version[:16]}…  "
          f"normalization {versions.normalization_snapshot_version[:16]}…")
    print(f"{LEAD}budgets    steps={asked.budgets.steps} "
          f"tokens={asked.budgets.tokens:,} "
          f"wall_clock={asked.budgets.wall_clock_seconds}s "
          f"live_queries={asked.budgets.live_queries}   "
          f"{DIM}steps=0 and live_queries=0 IS 'no tools', as policy{RESET}")
    rendered = asked.rendering
    print(f"{LEAD}rendering  {rendered.version} · {len(rendered.sections)} sections · "
          f"{sum(len(s.body) for s in rendered.sections):,} characters · "
          f"{len(rendered.evidence_ids)} citable evidence id(s)")
    for section in rendered.sections:
        dropped = section.truncation
        mark = "" if dropped is None else (
            f"   {YELLOW}truncated: kept {dropped.kept} of {dropped.total}{RESET}")
        print(f"{LEAD}  {DIM}{section.section:<22}{RESET} {len(section.body):>6,} chars  "
              f"{len(section.evidence_ids):>2} id(s){mark}")
    print(f"{LEAD}escalation escalates={escalation.escalates}  "
          f"{escalation.claims_read} claim(s) read  "
          f"{len(escalation.candidates)} candidate(s)  "
          f"{len(escalation.gaps)} gap(s)")


def show_outcome(assessment: Any, *, elapsed: float) -> None:
    outcome = assessment.triage
    if isinstance(outcome, policy.GateDecision):
        print(f"{LEAD}gate       {YELLOW}{verdict_text(outcome)}{RESET}")
        print(f"{LEAD}           {DIM}no prompt was built and no model was called; the "
              f"stored assessment's model_version is NULL,{RESET}")
        print(f"{LEAD}           {DIM}which is the fact rather than an omission "
              f"(ADR-0047 §3), and docs/hazards.md §11 is what it costs{RESET}")
    else:
        print(f"{LEAD}triage     {verdict_text(outcome)}")
    print(f"{LEAD}routed     {assessment.trigger or 'finished — nothing to analyse'}")
    if assessment.analysis is not None:
        print(f"{LEAD}analyst    {verdict_text(assessment.analysis.outcome)}")
        decision = assessment.analysis.decision
        if decision is not None:
            colour = GREEN if decision.outcome == "permitted" else YELLOW
            print(f"{LEAD}composed   {colour}{decision.outcome}{RESET}: proposed "
                  f"{decision.proposed} → permits {decision.permits}"
                  + (f"   held by {[found.rule for found in decision.findings]}"
                     if decision.findings else ""))
    print(f"{LEAD}{BOLD}terminal   {verdict_text(assessment.terminal)}{RESET}"
          f"   {DIM}in {elapsed:.1f}s{RESET}")


#: Fields every line of one window's log repeats, and that the six lines above
#: it on the terminal have already said. Dropped from the summary and kept in
#: the file, which is where a line is read whole.
ALREADY_ON_SCREEN = frozenset({"host", "context_version"})


def show_log(events: list[dict[str, Any]]) -> None:
    """The run's own structured log, the lines a deployment would ship."""
    if not events:
        return
    width = max(len(event["event"]) for event in events)
    room = 96 - width
    print(f"{LEAD}{DIM}the run's own log — {len(events)} line(s), "
          f"the file keeps them whole:{RESET}")
    for event in events:
        fields = " ".join(
            f"{name}={value}"
            for name, value in (event.get("fields") or {}).items()
            if name not in ALREADY_ON_SCREEN
        )
        print(f"{LEAD}  {DIM}{event['event']:<{width}} {fields[:room]}"
              f"{'…' if len(fields) > room else ''}{RESET}")


def assessment_document(
    asked: Any, assessment: Any, watch: Watch, events: list[dict[str, Any]],
    *, elapsed: float,
) -> dict[str, Any]:
    """One window's assessment, whole: what was sent, what came back, what it became.

    The request is dumped entire — the rendering with its five bodies, the
    truncation records, the evidence ids and the version set — because that
    object *is* what the model was shown, and a file that summarised it would be
    the second copy `concept/instruction.md` §2 refuses. `exchanges` is what
    went on the wire under it, per attempt, and the two are not the same thing:
    a retry carries a third message the request never held.
    """
    analysis = assessment.analysis
    return {
        "summary": {
            "host": asked.host,
            "window_start": f"{asked.window_start:%Y-%m-%dT%H:%M:%SZ}",
            "context_id": asked.context_id,
            "reached": (
                "gate" if isinstance(assessment.triage, policy.GateDecision)
                else "analyst" if assessment.trigger else "triage"
            ),
            "trigger": assessment.trigger,
            "terminal": verdict_text(assessment.terminal),
            "model_calls": len(watch.exchanges),
            "seconds": round(elapsed, 3),
        },
        "request": dumped(asked),
        "escalation": dumped(assessment.escalation),
        "exchanges": watch.exchanges,
        "outcome": {
            "triage": dumped(assessment.triage),
            "trigger": assessment.trigger,
            "analyst_request": dumped(assessment.analyst_request),
            "analysis": None if analysis is None else {
                "outcome": dumped(analysis.outcome),
                "decision": dumped(analysis.decision),
                "retrievals": len(analysis.retrievals),
            },
        },
        # What left the monitored network, per `concept/03`: hosted inference is
        # egress and the disclosure rule applies to a prompt as much as to a
        # lookup. One row per attempt, recorded before the call was made.
        "disclosures": {
            "triage": [dumped(row) for row in assessment.triage_disclosures.rows],
            "analyst": (
                [] if assessment.analyst_disclosures is None
                else [dumped(row) for row in assessment.analyst_disclosures.rows]
            ),
        },
        "log": events,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exercise", default=DEFAULT_EXERCISE)
    parser.add_argument(
        "--domains-only",
        action="store_true",
        help="plant only the domain indicators, which is what docs/hazards.md §5 "
             "was measured with: the scope test does not reach domain entities, so "
             "nothing escalates deterministically however high the confidence.",
    )
    parser.add_argument(
        "--windows",
        type=int,
        default=3,
        help="assess the first N windows in time order (0 = all). Every context "
             "holding a claim escalates, and one analyst run is minutes.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=OUTPUT,
        metavar="DIR",
        help=f"where this run writes itself down (default {where(OUTPUT)}): one "
             f"YAML per computed context, one per assessed window, and a "
             f"run.yaml saying what it all ran under",
    )
    parser.add_argument(
        "--show-prompt",
        action="store_true",
        help=f"print the messages sent to the model in full rather than the "
             f"first {PREVIEW} characters of each. The files hold them whole "
             f"either way.",
    )
    arguments = parser.parse_args(argv)

    print(f"{BOLD}MAESTRO HELENA — one real infection, end to end{RESET}")
    rule()
    began_at = datetime.now(timezone.utc)
    run = arguments.out / arguments.exercise / f"{began_at:%Y%m%dT%H%M%SZ}"
    records = records_of(arguments.exercise)
    host = infected_host(records)
    chain = CHAINS.get(arguments.exercise, ())
    source_first = min(record["ts"] for record in records)
    source_last = max(record["ts"] for record in records)
    print(f"  exercise     {BOLD}{arguments.exercise}{RESET}  "
          f"({len(records)} connections)")
    print(f"  infected     {BOLD}{host}{RESET}  "
          f"{sum(1 for r in records if r['ip']['src'] == host)} of {len(records)} records")
    print(f"  captured     {utc(source_first):%Y-%m-%d %H:%M} → {utc(source_last):%H:%M} UTC")
    print(f"  writing      {where(run)}/")
    note("real traffic: the hosts, the DNS chain, the TLS parameters and the timing")
    note("one file per computed context, one per assessed window, and a run.yaml")

    settings = settings_for()
    redactor = Redactor.from_settings(settings)

    stage(1, "What the live feed already knows about this capture")
    export = enrichment.fetch_threatfox(THREATFOX_EXPORT_URL, redactor=redactor)
    shared = overlap(export, records)
    print(f"  fetched      {len(export):,} bytes from ThreatFox")
    if shared:
        print(f"  {GREEN}already listed{RESET}  {sorted(shared)}")
        note("a real match — nothing needs adding for those")
    else:
        print(f"  {YELLOW}overlap: none{RESET}")
        note("not one address and not one domain of this capture is in the current")
        note("export. The recent feed is a rolling two-day sighting window; a")
        note("specific intrusion is not in it. THAT IS THIS DEMO'S REAL RESULT:")
        note("a pipeline that only knew what a feed lists would call this normal.")

    if arguments.domains_only:
        chain = tuple((value, kind) for value, kind in chain if kind == "domain")
        print(f"\n  {YELLOW}--domains-only{RESET}: planting the domains and nothing else,")
        note("which is how docs/hazards.md §5 was measured")
    if not chain:
        raise SystemExit(
            f"no chain is recorded for {arguments.exercise!r}, so this demo has "
            f"nothing to tell the feed about. CHAINS in this file is read off "
            f"each capture's own DNS and TLS; add the exercise there first."
        )
    print(f"\n  {YELLOW}ADDED to the snapshot{RESET}, because the feed does not list them:")
    for value, kind in chain:
        print(f"    {YELLOW}{kind:<8}{RESET} {value[:64]}")
    if arguments.domains_only:
        note("domains only — the scope test does not reach a domain entity, so")
        note("this is the run where nothing escalates however high the confidence")
    else:
        note("all three types the source covers, so the join can be seen matching")
        note("more than one")
    note("these are things the host really reached; the LISTING is the demo's")

    # The capture ends now, so every window has closed and can be assessed. A
    # capture rebased to START now spans into the future and its windows never
    # close. `scripts/rebase_capture.py` is the same operation for a corpus.
    delta = datetime.now(timezone.utc).timestamp() - source_last - 60.0
    moved = [{**record, "ts": record["ts"] + delta} for record in records]
    window_start = utc(source_first + delta)

    with schema(settings) as (connection, name):
        stage(2, "Ingest the capture, re-stamped so its windows have closed")
        suffixes = load_suffixes(connection, settings, when=window_start - timedelta(minutes=10))
        with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
            # Staged here rather than through `_common.stage_capture`, which
            # collapses a capture into ONE window: this one keeps its own 21
            # minutes, because the point is a host moving through the infection
            # over several windows rather than a single context.
            capture = staged(moved, Path(staging))
            counts = ingest(settings, connection, capture)
        print(f"  schema       {name}")
        print(f"  shifted      {delta / 86400:+.1f} days, so the capture ends a minute ago")
        print(f"  normalized   {counts.normalized}, quarantined "
              f"{counts.quarantine.quarantined}")
        if not counts.complete:
            print(f"  {RED}counters do not reconcile{RESET}")

        stage(3, "Load the snapshot: what ThreatFox published, plus the chain")
        load = load_feed(
            connection, settings, when=window_start - timedelta(minutes=5),
            raw=listed(export, chain),
        )
        if load.outcome == enrichment.FAILED:
            raise SystemExit(f"the feed did not load: {load.failure_reason}")
        connection.execute("FLUSH")
        (snapshot,) = connection.execute(
            "SELECT snapshot_version FROM helena_reference_feed_snapshot_validity "
            "WHERE tenant = %s AND sensor = %s AND valid_from <= %s "
            "AND (valid_to IS NULL OR valid_to > %s)",
            (settings.identity.tenant, settings.identity.sensor, window_start, window_start),
        ).fetchone()
        print(f"  snapshot     {snapshot[:16]}…  "
              f"{(load.counts or {}).get('claims_stored', 0)} claims")

        stage(4, "What the enrichment join matched, by entity type")
        matched = connection.execute(
            "SELECT entity_type, status, "
            "       coalesce(classification, '(no snapshot consulted)'), "
            "       count(*), count(DISTINCT entity_value) "
            "FROM helena_analytical_enriched_context "
            "GROUP BY 1, 2, 3 ORDER BY 1, 3 DESC, 2"
        ).fetchall()
        print(f"  {'entity type':<13} {'status':<8} {'what the snapshot said':<26} "
              f"{'rows':>5} {'distinct':>9}")
        rule()
        for entity_type, status, classification, rows, distinct in matched:
            hit = classification not in ("no_match", "(no snapshot consulted)")
            colour = (GREEN + BOLD) if hit else DIM
            print(f"  {entity_type:<13} {status:<8} {colour}{classification:<26}{RESET}"
                  f" {rows:>5} {distinct:>9}")
        note("`no_match` is a snapshot consulted and saying nothing about that entity —")
        note("a real answer about a real indicator, and not a statement of safety")
        hits = connection.execute(
            "SELECT entity_type, entity_value, source_id, confidence, port_matched "
            "FROM helena_analytical_enriched_context "
            "WHERE classification NOT IN ('no_match') AND classification IS NOT NULL "
            "GROUP BY 1,2,3,4,5 ORDER BY 1, 2"
        ).fetchall()
        if hits:
            print(f"\n  {GREEN}the entities a claim was made about{RESET}:")
            for entity_type, value, source, confidence, port_matched in hits:
                port = "" if port_matched is None else f"  port_matched={port_matched}"
                print(f"    {entity_type:<9} {value[:46]:<46} {source} "
                      f"{confidence}{port}")
            note("port_matched qualifies an address match, it does not filter it (ADR-0042)")

        stage(5, "The contexts the engine computed, and what was claimed about them")
        contexts = live_contexts(connection)
        store = rendering.RenderingStore(connection=connection, identity=settings.identity)
        projections = [store.project(context_id) for context_id in contexts]
        projections.sort(key=lambda p: p.statistics.window_start)
        rules = policy.version(policy_v1.POLICY_VERSION)
        thresholds = policy.thresholds()
        gate = policy.triage_gate()
        print(f"  contexts     {len(projections)} "
              f"({len(set(p.host for p in projections))} host(s) x 5-minute windows)")
        rule()
        print(f"  {'window':<8} {'host':<15} {'entities':<9} {'claims':<7} escalates")
        escalations = {}
        contexts_written: list[Path] = []
        held: set[tuple[str, str]] = set()
        for projection in projections:
            supports = policy.supports_in(projection)
            escalation = rules.escalate(supports, thresholds)
            escalations[projection.context_id] = escalation
            mark = GREEN if escalation.escalates else DIM
            print(f"  {projection.statistics.window_start:%H:%M}    "
                  f"{projection.host:<15} {len(projection.entities):<9} "
                  f"{escalation.claims_read:<7} {mark}{escalation.escalates}{RESET}")
            if escalation.claims_read and not escalation.escalates:
                held.update(
                    (candidate.entity_type, rule)
                    for candidate in escalation.candidates
                    for rule in candidate.rules
                )
                shown = [c for c in escalation.candidates if not c.escalates][:2]
                for candidate in shown:
                    print(f"    {DIM}{candidate.entity_type} {candidate.entity_value[:30]}"
                          f"  supports={candidate.supports}  held by {list(candidate.rules)}{RESET}")
            # The line above is an index entry, not a context: five columns hold
            # neither the entities nor the claims nor the candidates the rules
            # declined, and those three are what a context IS. So each one is
            # written out whole beside the run.
            contexts_written.append(
                write_yaml(
                    run / "contexts" / (
                        f"{projection.statistics.window_start:%H%M}"
                        f"-{slug(projection.host)}"
                        f"-{projection.context_id[:12]}.yaml"
                    ),
                    context_document(projection, supports, escalation),
                    about=f"context {projection.context_id} — {projection.host} at "
                          f"{projection.statistics.window_start:%Y-%m-%dT%H:%M:%SZ}",
                )
            )
        print()
        print(f"  {BOLD}{len(contexts_written)} context file(s){RESET} under "
              f"{where(run / 'contexts')}/")
        note("every entity with one enrichment record per source, every claim with")
        note("the traffic of the entity it is about, and every candidate the rules")
        note("considered — the ones that did not escalate with the rule that held")
        note("each back")
        for written_path in contexts_written[:3]:
            print(f"    {DIM}{written_path.name}{RESET}")
        if len(contexts_written) > 3:
            print(f"    {DIM}… and {len(contexts_written) - 3} more{RESET}")

        stage(6, "Assess the contexts against the configured model")
        budget_policy = budgets.load()
        triage_prompt, analyst_prompt = triage.version("v1"), analyst.version("v1")
        retry = agents.RetryPolicy(attempts=3)
        # One buffer for the demo's own log AND the two agents': every
        # `ModelClient` builds a logger, and one without a stream writes to the
        # terminal. Nineteen JSON lines over the top of the output is how that
        # was found. Drained per window rather than discarded, because those
        # lines are the pipeline's own account of what it just did and throwing
        # them away made this demo hide the one record an operator would read.
        log = io.StringIO()
        logger = observability.StructuredLogger(
            component="demo", tenant=settings.identity.tenant,
            sensor=settings.identity.sensor, redactor=redactor, stream=log,
        )
        assessments = orchestration.AssessmentStore(
            connection=connection, prices=budgets.model_prices()
        )
        # Built once and pointed at each window's watch in turn. `Watched` is
        # the shipped client with observation added, not a second one.
        triage_client = Watched.for_agent(settings, "triage", stream=log)
        analyst_client = Watched.for_agent(settings, "analyst", stream=log)
        offered = triage.classifications("v1")
        print(f"  triage       {BOLD}{triage_client.model_requested}{RESET} "
              f"at {triage_client.endpoint_host}   "
              f"{DIM}{resolved_from(settings.triage.source)}{RESET}")
        print(f"  analyst      {BOLD}{analyst_client.model_requested}{RESET} "
              f"at {analyst_client.endpoint_host}   "
              f"{DIM}{resolved_from(settings.analyst.source)}{RESET}")
        print(f"  prompts      triage {triage_prompt.version} "
              f"(proposes {list(triage_prompt.propose)}) · "
              f"analyst {analyst_prompt.version}")
        print(f"  verdicts     {list(offered)}   "
              f"{DIM}closed per taxonomy version, looked up rather than "
              f"written down{RESET}")
        print(f"  retry        {retry.attempts} bounded attempt(s); a "
              f"schema-invalid answer is retried, a verdict is not")
        print(f"  gate         min_suspicious_indicators="
              f"{gate.min_suspicious_indicators} ({gate.triage_gate_version})   "
              f"{DIM}evaluated after the escalation, never before it{RESET}")
        # The INFECTED HOST's windows, in time order. Not a cherry-pick of
        # results: the host is chosen before any assessment runs, by traffic
        # volume, and this demo is about it -- the other two "hosts" in this
        # capture are a broadcast address and a gateway with one record each.
        # A prefix over every context instead put the two of those first and
        # assessed nothing that mattered. `--windows 0` runs all of the host's.
        mine = [p for p in projections if p.host == host]
        assessed = mine if arguments.windows == 0 else mine[: arguments.windows]
        if len(assessed) < len(projections):
            print(f"  {YELLOW}first {len(assessed)} of {len(mine)} windows for {host}{RESET} "
                  f"{DIM}(--windows 0 for all){RESET}")
        outcomes = []
        assessments_written: list[Path] = []
        for number, projection in enumerate(assessed, start=1):
            rule()
            print(f"  {BOLD}{CYAN}[{number}/{len(assessed)}]{RESET} "
                  f"{BOLD}{projection.statistics.window_start:%H:%M}–"
                  f"{projection.statistics.window_end:%H:%M}Z{RESET}  "
                  f"{projection.host}   {DIM}{len(projection.entities)} entities, "
                  f"{projection.statistics.flow_count} flows, "
                  f"{projection.statistics.completeness}{RESET}")
            asked = request_for(
                projection, connection=connection, settings=settings,
                snapshot=snapshot, normalization=suffixes.snapshot_version,
                budget_policy=budget_policy, prompt=triage_prompt,
            )
            show_request(asked, escalations[projection.context_id])
            watch = Watch(show_prompt=arguments.show_prompt)
            began = time.monotonic()
            assessment = orchestration.assess(
                asked,
                projection=projection,
                triage_client=triage_client.observing(watch, agent="triage"),
                analyst_client=analyst_client.observing(watch, agent="analyst"),
                retry=retry,
                triage_prompt=triage_prompt,
                analyst_prompt=analyst_prompt,
                provider_tools=(),
                thresholds=thresholds,
                budget_policy=budget_policy,
                send_policy=disclosure.send_policy(),
                inherit=analyst.Inheritance(inherit_triage_rationale=False),
                logger=logger,
                triage_gate=gate,
            )
            spent = time.monotonic() - began
            assessments.store(assessment, at=datetime.now(timezone.utc))
            outcomes.append((projection, assessment))
            show_outcome(assessment, elapsed=spent)
            events = drained(log)
            show_log(events)
            assessments_written.append(
                write_yaml(
                    run / "assessments"
                    / f"{projection.statistics.window_start:%H%M}.yaml",
                    assessment_document(
                        asked, assessment, watch, events, elapsed=spent
                    ),
                    about=f"assessment of {projection.context_id} — "
                          f"{projection.host} at "
                          f"{projection.statistics.window_start:%Y-%m-%dT%H:%M:%SZ}",
                )
            )
            print(f"{LEAD}{BOLD}written{RESET}    "
                  f"{where(assessments_written[-1])}", flush=True)
        rule()
        connection.execute("FLUSH")

        stage(7, "What a consumer reads off the output topic")
        sink_store = sink.SinkStore(connection=connection, identity=settings.identity)
        print(f"  pending      {sink_store.pending()} message(s)")
        cited = 0
        for identifier in sink_store.terminal():
            message = sink_store.project(identifier)
            hits = [
                (entity.entity_value, evidence.classification)
                for entity in message.entities
                for evidence in entity.evidence
                if evidence.classification not in (None, "no_match")
            ]
            cited += len(message.citations)
            mark = GREEN if message.verdict and message.verdict != "normal" else DIM
            print(f"  {message.window_start:%H:%M}    "
                  f"{message.outcome_kind:<13} "
                  f"{mark}{str(message.verdict or message.failure_reason):<12}{RESET}"
                  f" {len(message.citations)} citation(s)"
                  f"{'  ← ' + ', '.join(v for v, _ in hits[:2]) if hits else ''}")

        banner("WHAT THIS RUN SHOWED")
        escalated = sum(1 for _, a in outcomes if a.trigger)
        gated_count = sum(
            1 for _, a in outcomes if isinstance(a.triage, policy.GateDecision)
        )
        # What this run ran under, beside what it produced. A file of verdicts
        # without the snapshot, the thresholds and the models that decided them
        # is a result nobody can reproduce or argue with -- `concept/04` puts the
        # version set on every assessment for the same reason, and this is the
        # run-level copy of that habit.
        summary = write_yaml(
            run / "run.yaml",
            {
                "demo": "assess_an_infection",
                "exercise": arguments.exercise,
                "began_at": f"{began_at:%Y-%m-%dT%H:%M:%SZ}",
                "finished_at": f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
                "capture": {
                    "records": len(records),
                    "infected_host": host,
                    "records_from_that_host": sum(
                        1 for r in records if r["ip"]["src"] == host
                    ),
                    "captured_from": f"{utc(source_first):%Y-%m-%dT%H:%M:%SZ}",
                    "captured_to": f"{utc(source_last):%Y-%m-%dT%H:%M:%SZ}",
                    "shifted_seconds": round(delta, 3),
                    "shifted_days": round(delta / 86400, 2),
                    "normalized": counts.normalized,
                    "quarantined": counts.quarantine.quarantined,
                    "counters_reconcile": counts.complete,
                },
                "feed": {
                    "export_url": THREATFOX_EXPORT_URL,
                    "export_bytes": len(export),
                    "overlap_with_the_published_export": sorted(shared),
                    "added_by_this_demo": [
                        {"value": value, "kind": kind} for value, kind in chain
                    ],
                    "snapshot_version": snapshot,
                    "claims_stored": (load.counts or {}).get("claims_stored", 0),
                    "normalization_snapshot_version": suffixes.snapshot_version,
                },
                "engine": {"schema": name},
                "models": {
                    "triage": {
                        "model_requested": triage_client.model_requested,
                        "endpoint_host": triage_client.endpoint_host,
                        "resolved_from": dict(settings.triage.source),
                    },
                    "analyst": {
                        "model_requested": analyst_client.model_requested,
                        "endpoint_host": analyst_client.endpoint_host,
                        "resolved_from": dict(settings.analyst.source),
                    },
                    "temperature": agents.TEMPERATURE,
                    "retry_attempts": retry.attempts,
                },
                "policy": {
                    "thresholds": dumped(thresholds),
                    "triage_gate": dumped(gate),
                    "budgets": {
                        "triage": dumped(budget_policy.for_emitter(TRIAGE)),
                        "analyst": dumped(
                            budget_policy.for_emitter(analyst.EMITTER)
                        ),
                    },
                    "rendering_budget_characters": rendering.budget().characters,
                    "prompt_versions": {
                        "triage": triage_prompt.version,
                        "analyst": analyst_prompt.version,
                    },
                },
                "produced": {
                    "contexts": [path.name for path in contexts_written],
                    "assessments": [path.name for path in assessments_written],
                    "windows_assessed": len(assessed),
                    "windows_of_the_infected_host": len(mine),
                    "contexts_in_the_capture": len(projections),
                    "reached_the_analyst": escalated,
                    "cleared_by_the_gate": gated_count,
                    "citations_on_the_topic": cited,
                },
            },
            about=f"demo 9 over exercise {arguments.exercise}: what this run ran "
                  f"under, and what it produced",
        )
        print(f"\n  {len(assessed)} of {len(mine)} window(s) of {host} assessed, "
              f"out of {len(projections)} contexts in the capture")
        print(f"  {escalated} reached the analyst, {gated_count} cleared by the gate")
        print(f"  {cited} citation(s) to stored evidence on the topic")
        print(f"\n  {BOLD}{where(run)}/{RESET}")
        print(f"    {DIM}contexts/     {len(contexts_written)} file(s) — entities, "
              f"claims, and every candidate the rules declined{RESET}")
        print(f"    {DIM}assessments/  {len(assessments_written)} file(s) — the "
              f"request, the wire, the answer as text, the log{RESET}")
        print(f"    {DIM}{summary.name}      what it all ran under{RESET}")
        print(
            f"\n{DIM}  The connections were real: this host really contacted that chain,\n"
            f"  in that order. Two things were not. The timestamps were moved so a\n"
            f"  loadable snapshot could cover the windows, and the feed was told\n"
            f"  about the chain — because it does not know it. Nothing here is\n"
            f"  evidence that the pipeline would have FOUND this infection; it is\n"
            f"  what the pipeline does with an infection once something lists it.\n\n"
            f"  The gap between those two sentences is the one docs/hazards.md §11\n"
            f"  records, and it is why the pre-triage gate's cost is unmeasured.{RESET}"
        )

        if held:
            banner("A HIGH-CONFIDENCE MATCH THAT DID NOT ESCALATE")
            print()
            for entity_type, rule_name in sorted(held):
                print(f"  {YELLOW}{entity_type:<12}{RESET} held by {BOLD}{rule_name}{RESET}")
            print(
                f"\n{DIM}  Those claims are confidence 1.0 on a host that really was\n"
                f"  compromised, and the deterministic escalation did not fire. The rule\n"
                f"  that held each one back is named above, read off the run rather than\n"
                f"  argued here. If the entity type is `domain`, this is the scope-test\n"
                f"  gap docs/hazards.md §5 records -- 'the composition rule works on\n"
                f"  address entities and not on domain ones, and the feeds most likely to\n"
                f"  hit list domains' -- happening on real malware traffic rather than in\n"
                f"  a paragraph.{RESET}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
