# 0018 — The triage rendering: the five parts, the line grammar, and the TLS subset

**Status: accepted.** Task 28 (D4 Rendering).
**Authority:** `concept/04-the-two-agents.md` ("What the Triage Agent sees" — the
five parts and the four properties), `concept/03-architecture.md` (the enrichment
join is per entity; the triage rendering shows enrichment-tier evidence only),
`concept/05-threat-intelligence.md` (the declared entity types on a source
descriptor, the retained native payload, tiers),
`concept/07-principles.md` (visible truncation, retrieved provider text is data),
`concept/instruction.md` §2 (the five statuses stay distinct *including in
whatever is rendered to an agent*; absence is not emptiness),
`docs/decisions/0008-version-registry.md` (renderings are frozen version modules)
and `docs/decisions/0017-the-agent-contract.md` (the five closed section names,
`RenderedSection.evidence_ids`, `Truncation`).

`helena.rendering` is the fourth versioned package: `__init__.py` holds the
machinery — the read-out from the engine and the loader — and `v1.py` holds the
frozen five-part rendering. `sql/migrations/0016_triage_rendering_inputs.sql`
supplies what the engine did not yet expose. `tests/test_rendering.py` exercises
both.

---

## 1. The five parts, and where each comes from

| Part | Read from | Cites |
| --- | --- | --- |
| `host` | `helena.hosts` — fixed configuration only | nothing |
| `domains_contacted` | the `domain` entities, and what the enriched context says about them | every domain claim |
| `addresses_contacted` | the `address` entities, plus `helena_signal_context_entity_ports` | every address claim |
| `tls_parameters` | `helena_signal_context_tls`, plus the `fingerprint` entities | every fingerprint claim |
| `connection_statistics` | `helena_signal_host_context_live` | nothing |

**The entity list is `helena_signal_context_entities`' and the claims are
`helena_analytical_enriched_context`'s.** That split is not a convenience and it
is the decision this task got wrong first. The enriched context's source list is
the snapshot ledger — every source that has ever been *asked* — so before any
feed has ever loaded it yields **no rows at all**, which
`sql/migrations/0015_enriched_context.sql` states as a consequence and which the
first draft of this renderer walked straight into: a deployment whose only fault
was that no feed had run yet rendered as a host that contacted nothing. So the
entities come from the view that knows what a context observed, and what is
*known* about them comes from the view that knows that.

It has a second payoff. `sql/migrations/0015` projects three of the five
observation flags, because three is what the composition rule reads; that is the
right subset for a rule about *scope* and the wrong one for a rendering about
*observation*. Reading the entity rows directly gives all five and the
`fingerprint_algorithm` beside them, with no migration and no superseded
definition.

Two of the five cite nothing and that is not an omission. `concept/04` requires a
stable evidence identifier on every **enriched** value; a configured host
attribute is not one, and a citation in the host section would point at
configuration as though a source had claimed it. The connection statistics are
measurements rather than claims, which is what
`helena.contracts.v1.RenderedSection.evidence_ids` already says in its own
docstring.

`helena_signal_host_context_live` and not `helena_signal_host_context`, because
the request carries *"the context reference **and its version**, which is what
makes replay possible"* and the live view is the one object that defines what a
citation pins (`sql/migrations/0009_retention_boundary.sql`). The consequence is
that a context outside the retention boundary raises
`helena.context.ContextOutsideRetention` rather than rendering as a host that did
nothing — which is correct, and which is why every engine test here re-stamps its
records into the current window the way `tests/test_context.py` does.

## 2. The fingerprints are in part four

`concept/04` closes the rendering at five parts and none of them is named after a
fingerprint. A JA3 **is** a TLS parameter — a fingerprint of the ClientHello — so
the `fingerprint` entities are rendered in `tls_parameters`, after the negotiated
tuples. It is the one entity type whose section is not named after it, which is
why `helena.rendering.v1.SECTION_ENTITY_TYPES` writes it down rather than
inferring it from a name.

That placement is also what gives part four the enrichment it would otherwise
have none of: `sslbl-ja3` declares `fingerprint` as its entity type, so the
section carries a source header, a status per record and an evidence identifier
wherever there is a claim.

## 3. The TLS parameter subset, and the criterion that chose it

`concept/04`: *"selected TLS parameters — a subset, not everything the record
carries."* The task asked for the criterion in a decision note rather than in a
comment, so that the next person can disagree with the criterion instead of with
a list.

**A TLS parameter is selected when all three hold:**

1. it is **negotiated or offered in the handshake** — a property of the
   cryptographic session rather than of how much traffic went over it;
2. it is **low-cardinality per host-window**, so the section's size grows with
   the number of distinct configurations a host used and not with the number of
   connections it opened;
3. it is **not already a record of its own elsewhere in the projection** — two
   copies of one value can disagree, and the one that carries a claim is the one
   that matters.

**Selected:** `client_version`, `server_version` and `server_cipher`, as a tuple
with the number of flows that negotiated it (`helena_signal_context_tls`), and
the client `ja3` / `ja4` fingerprints, which arrive as entities.

**Rejected, each under the rule it fails:**

| Parameter | Rule | Why |
| --- | --- | --- |
| `sni` (server name) | 3 | It is already a `domain` record in part two, with `tls` among its observing layers — which is exactly the distinction `concept/04` asks part two to make. A second copy here could disagree with the one a claim attaches to |
| `ja3s` / `ja4s` (server fingerprints) | 3 | They describe the server, and what this projection says about a server is the address record. `sql/migrations/0010` does not extract them as entities and no registered source is about them, so a rendered `ja3s` would be a value with no claim and no reader |
| `alpn` | — | Not in the store: `helena_flatten_tls` carries `alpn_count` and not the negotiated protocol values. A count of offered protocols is not a parameter, and adding the values is a flatten-layer change no note asks for |
| `recs` / `record_count` | 1 | The TLS record count is traffic volume, and volume is part five |

**The values are rendered exactly as the sensor reported them** — `0303`, `C030`
— and are not translated into `TLS 1.2` or a cipher-suite name. The translation
table is an external fact this repository does not hold, and inventing one is the
class of error this project has already had to correct more than once. A model
that knows the registry can read the hex; one that does not would be no better
served by a name this repository guessed.

## 4. The line grammar

Every record is **one line**, of `kind value key=value ...`, and the enrichment of
a record is appended to that record's own line behind ` | `.

- **A claim can never be separated from the entity it is about.** The next
  increment bounds this rendering and drops records to fit; a shape where the
  claim sat on a continuation line would let a budget keep the entity and drop
  the claim, which is the quiet version of *silent truncation is a correctness
  bug*.
- **What was dropped is countable in lines.** `Truncation.kept` and
  `Truncation.total` count records, and a record is a line.

Values go through `helena.rendering.v1.token`, which percent-encodes anything
that is not a printable non-space ASCII character. An entity value is
attacker-influenced text — a domain name comes from a DNS query — and a name
carrying a newline would forge a second line in a section. It is the same forgery
`helena.hosts` refuses in a configured attribute value, arriving from the other
side. Percent-encoding rather than refusal, because refusing would drop the one
entity most worth looking at.

A section with no records renders `none observed in this window` and never a
blank body: *absence is not emptiness*, and a blank section would make "this host
contacted no domains" and "the domain section was not rendered" the same thing.

## 5. The status and the classification are two tokens, and freshness is one line

`concept/instruction.md` §7: the five states stay distinct *"including in whatever
is rendered to an agent"*. So every enrichment segment carries `status=` — what
happened to the lookup — and carries `classification=` **only where the source
answered**. These are the two lines the whole stage exists to keep apart:

```
... | sslbl-ja3 status=missing
... | threatfox status=ok classification=no_match
```

The first is a fingerprint nobody could look up. The second is a name that was
looked up and is not listed. A `missing` or `failed` lookup produced no taxonomy
object at all (`concept/05` rule 4) and writing one there — even the word `none`
— would be a fifth value standing for something `status` already says.

**Freshness is stated once per source, in the section header**, not once per
record:

```
source threatfox tier=B status=ok snapshot=<sha256> loaded=<iso8601>
```

That is not a shortcut. The status and the snapshot are properties of *(window,
load history)* and not of an entity — every entity in one window sees the same
snapshot from the same source — and `helena.rendering` **raises** rather than
writing a header for rows that disagree. Repeating a 64-character snapshot
digest on every record would have been the same fact thirty times over, in the
one place where size is the constraint.

The per-record `status=` is deliberately redundant with the header's. The two
cannot drift — the renderer refuses to emit the header unless every record agrees
with it — and the task asks for the status to be explicit *per record*, because
that is where a reader is when the question arises.

**`source_tier` comes from `helena.enrichment.SOURCES` and never from the row.**
A source's A–D tier is a governed decision (`concept/05`), and the row's copy of
it is NULL on exactly the rows that matter most here: the ones with no claim.

## 6. A source that has never loaded gets a record anyway

`sql/migrations/0015_enriched_context.sql` takes the enriched context's source
list from the snapshot ledger — every source that has ever been *asked* — and
states the consequence: a registered source that has never attempted a load
produces **no rows at all**, not `missing` rows.

A renderer that showed only the rows it found would render a fingerprint nobody
could look up as a fingerprint with nothing against it, which is the exact
failure `concept/04` names ("a domain nobody could look up must not read as a
clean domain"). So the rendering iterates `helena.enrichment.SOURCES`, and a
source with no row for an entity gets `status=missing` — the same answer
`helena.enrichment.feed_status` gives for the same source, for the same reason.

A source whose declared entity types do **not** cover the entity gets no segment
at all, which is a third thing and not `missing`: `concept/05` puts the entity
types on the descriptor because *"a JA3 list has nothing to say about a domain"*,
and `sslbl-ja3 status=missing` beside a domain would claim the list was asked and
could not answer.

## 7. The tier filter, and the trap in it

`concept/03`: *"the triage rendering shows enrichment-tier evidence only — without
that tag, a report fetched during one investigation would appear in the
precomputed context of every later host that talked to the same address, and
triage input would stop being uniform."*

The entity query filters on it, and it filters as an **allow-list with a null
arm**:

```sql
AND (evidence_tier IS NULL OR evidence_tier = 'enrichment')
```

The tier comes from a LEFT JOIN, so it is NULL on exactly the rows that carry no
claim: every `no_match`, every `missing`, every `failed`. A plain
`evidence_tier = 'enrichment'` would drop all of them and leave a rendering of
nothing but hits — and an enriched context is *mostly negative space*, so a
triage input showing only the matches is the same misreading as one showing none,
from the other side. Both arms are asserted, and the allow-list arm is asserted
by executing the query itself against a stand-in relation carrying an `analyst`
row, because nothing in this repository writes one yet.

`helena.enrichment.ENRICHMENT_TIER` is the Python copy of the literal in
`sql/migrations/0014_feed_mapping_views.sql`, and the two are asserted equal by
asking the engine what the evidence view produces.

## 8. What migration 0016 adds, and what it deliberately does not

**One object, and nothing is dropped or superseded.**
`helena_signal_context_tls` is a plain signal-layer view: the window is taken
over the flows because `helena_flatten_tls` carries no time column, and
`handshake_count` counts flows so that forty identical connections are one row
saying forty. Part four had no readable source in the engine; the other four did.

An earlier draft of this task also dropped and recreated
`helena_analytical_enriched_context` to add the two missing observation flags and
`fingerprint_algorithm`, and retrofitted `Superseded by:` into 0015 to pay for
it. That was the wrong fix and the tests found it: once the entity list has to
come from `helena_signal_context_entities` anyway — see §1 — the flags come with
it, and the migration bought nothing but a checksum break. It was backed out.
**The lesson is worth keeping: the enriched context answers "what is known about
this entity", not "what entities are there", and asking it the second question is
how a rendering ends up describing a host that did nothing.**

Three declaration blocks in applied migrations were retrofitted, and only for
accuracy: `helena_flatten_flows` and `helena_flatten_tls` (0005) and
`helena_signal_host_context` (0006) gain `helena_signal_context_tls` in their
`Read by:`, which `tests/test_view_layering.py` requires for a relation that
reads them; 0015 and 0009 gain the renderer in theirs, where the existing text
had become false ("nothing renders a context yet", "the enriched-context view is
the next reader"). Their checksums moved, and `docs/runbook.md` says what that
costs a store that has already migrated.

## 9. What this rendering deliberately does not carry

- **The publisher's native payload.** `helena_reference_evidence.native_evidence`
  holds the minimal fields that justify a mapping — malware name, tags, reporter,
  reference URL — and none of it is rendered. `concept/instruction.md` §6:
  *"treating retrieved provider text as instruction — it is data. Isolate it, and
  test the isolation."* Triage runs a small fast model on the high-volume path
  with no tools and no way to check anything it is told; feed text in that
  position is an instruction channel an indicator author can write to. What is
  rendered instead is the *mapped* value — a taxonomy path from a closed
  vocabulary, a numeric confidence, a scope, a tier, timestamps — and the
  evidence identifier, which is how the analyst tier or a human reaches the
  native record. **A rendering v2 that carries native text needs an isolation
  test before it needs a format.**
- **URL entities.** The five parts have no place for one, and folding a URL into
  the domain record would need the host-part extraction re-implemented here when
  it already has exactly one home. The cost is real and is stated rather than
  hidden: a URL-scoped claim is invisible to triage, and 287 of the 4 095
  indicators in the ThreatFox snapshot are `url`-typed. What covers most of it is
  that the URL's host is already a domain record carrying `http` among its
  layers — measured on the layer-coverage capture, all five hosts of its six URL
  entities are. Closing it properly is a rendering `v2` that renders a URL record
  in part two under its own kind, or an enrichment view that also attaches a URL
  claim to its host; both are decisions, not formatting.
- **Application identity and service identification.** `concept/04` asks part two
  for "type or class" and part three for "service identification", and no source
  in this repository supplies either: `helena.enrichment.SOURCES` has ThreatFox
  and SSLBL, and Netify — which `docs/decisions/0009-netify-application-identification.md`
  cleared as a Tier D source of exactly this — has no loader and no descriptor.
  Registering one is an enrichment-source decision (`concept/instruction.md` §3),
  not part of a rendering task. What part three carries in the meantime is the
  **destination ports the host actually reached**, which is observed service
  identification rather than an absent feed's.
- **A source's caveat.** `SourceDescriptor.caveat` is 600 characters for
  `sslbl-ja3` and it is real and relevant. It is deferred rather than dropped:
  the tier is rendered, which is the governed strength signal, and a paragraph
  per source is a budget decision that belongs with the budget (task 29).
- **The reason a load failed.** `status=failed` is distinct from `missing` and
  says the query did not complete; *why* it did not is on
  `helena_reference_feed_snapshot.failure_reason`, which 0015 does not project
  and 0016 did not add. It would make an operator-facing status actionable and
  changes nothing a triage verdict turns on.
- **A size budget and any truncation.** `concept/08-open-questions.md` lists the
  numeric budget values as open and `concept/07` makes budget values policy
  rather than constants in a branch. Task 29 is the increment that bounds this,
  and `helena.contracts.v1.Truncation` is the shape it lands in — so **no section
  produced here carries one**, and the rendering is honestly labelled unbounded
  until it does. What this increment does supply is the two things a budget
  needs: a neutral record order — `(entity_type, entity_value)`, deliberately not
  hits-first, because a truncation over a hits-first order would drop the
  negative space and hand triage a store that looks like nothing but threats —
  and a measurement. The ten-record layer-coverage capture, re-stamped into one
  window (14 domains, 15 addresses, 6 fingerprints, two TLS parameter tuples),
  renders to **4 964 characters** across the five sections with no feed ever
  loaded and **5 886** after a ThreatFox load that produced one hit. The
  difference is almost all of it the `classification=no_match` token on every
  record and the snapshot digest in two section headers; the enrichment adds
  about 19 % to a rendering, and one hit adds 190 characters.
