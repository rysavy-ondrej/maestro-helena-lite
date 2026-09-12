# 0042 — How a port qualifies an address match: a scope, a three-valued flag, and a policy rule

Status: accepted — 2026-09-12 (task 55, D9 Governance). **Recorded after the
fact.** The decision was taken across tasks 22, 26 and 30 and lives in
`sql/migrations/0014`, `sql/migrations/0015` and `helena.policy.v1`. This record
is where it becomes findable.

## The question this closes

`concept/08-open-questions.md`, blocking, enrichment: **how the port qualifies an
address match.** `concept/instruction.md` §6 lists the way to get it wrong by
name — *"an `ip:port` indicator joined against bare addresses"* — and the
consequence: *"split the port into its own column on the feed side — and keep it;
it qualifies the match."*

It is not a corner case. Measured over a real export on 2026-09-06: **3 139 of
4 985 entries (63 %) are `ip:port`, across 596 distinct ports.** ThreatFox has no
bare-`ip` indicator type at all.

## The answer, in four places

**1. The loader splits the port out and keeps both.**
`helena_reference_threatfox` carries `ioc_value` **as supplied** beside the
`entity_value` and `port` split out of it, so the reference table can be checked
against the export it came from. `port` is NULL for anything that is not
`ip:port`.

**2. The claim's scope carries the port, and the entity does not.** The entity is
the `address` — an address on a port is not a different kind of thing to look up
— so the qualification lives in the claim's scope:

```
scope_type  = 'address:port'          (otherwise the entity type)
scope_value = '<address>:<port>'      (otherwise the entity value)
```

`sql/migrations/0014_feed_mapping_views.sql` computes both, and the port is also
in the claim's native evidence. This is the shape the composition rule already
reads two columns for rather than a blob ([0041](0041-enrichment-status-representation.md)).

**3. The other side of the comparison is a signal-layer view.**
`helena_signal_context_entity_ports` is the ports a host actually reached on an
address in that window — a **plain VIEW**, one row per (port, address, context),
read by `helena_analytical_enriched_context`. It is in the signal layer and not
inlined into the analytical view for the reason the layering rule exists: the
analytical layer may not read the flatten layer.

**Destinations only.** A port on the source side is the host's own ephemeral port
and says nothing about what it reached, so `dst_port` is the one that can be
compared with a claim's scope.

**4. `port_matched` is three-valued and is not a filter.**

| Value | Meaning |
| --- | --- |
| NULL | the claim is not port-scoped; the question does not arise |
| true | the host reached that address on that port |
| false | the host reached that address on **other ports only** |

**A false row is kept.** `concept/02` says what to do with it and it is not "drop
it": that hit is `suspicious` at most rather than nothing at all. A view that
filtered it would be making the composition rule's decision on the rule's
behalf — so the decision is made where the traffic is, by
`helena.policy.v1`'s `_port_not_reached`, which constrains a proposed `malicious`
whose only address support is on a port the host never used.

That rule and `_traffic_not_bidirectional` never both fire: they are the two ways
address support fails, and a decision naming both would say the connection both
happened and did not.

`port_matched` is carried to the rendering, to the policy record and to the
emitted message (`helena.rendering`, `helena.policy`, `helena.sink`,
`sql/migrations/0019_sink.sql`), so the distinction an agent is shown is the
distinction a consumer receives.

## What this does not settle

- **Nothing equivalent exists for domains.** The scope test works on `address`
  entities and not on `domain` ones, which is a recorded hazard rather than an
  oversight — [`docs/hazards.md`](../hazards.md), *the scope-test gap on domains* —
  and the feeds most likely to be added list domains.
- **Whether keeping false rows over-alerts or under-alerts.** It is a threshold
  question and it needs the corpus. Unmeasured.
