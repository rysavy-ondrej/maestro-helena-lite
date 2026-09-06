# Instructions for the implementation agent

These are binding. The concept notes describe **what** HELENA is; this describes
**how it may be built**. Where a note and this file disagree, that is a defect —
say so rather than picking one.

The single failure mode these rules exist to prevent: **a prototype that runs and
lies**, and **a specification that is locally minimal at every step and globally
unbuildable**.

---

## 0. Before you write anything

1. **Read the concept notes for the area you are touching.** At minimum
   [07 — Principles](07-principles.md), which is the list of rules an
   implementation may not break, and the note covering your stage.
2. **Answer two questions in writing, in the increment's own record:**
   - *What assumption does this increment let us validate?* If the answer is
     "none, it makes the design complete", do not build it.
   - *What does this make **buildable** next?* Not what it makes complete.
3. **Check the artifact, not the page.** If the increment depends on an external
   thing — a feed's format, an API's endpoints, a binary's behaviour — **fetch it
   and look at it** before writing a line against it. Every wrong source record
   in this project came from a documentation page or a guessed convention,
   propagated before anyone fetched the thing it described. A count beats an
   adjective: "narrowest" was a feed with five rows.

---

## 1. Simplicity — what "simple" means here

**Build the smallest coherent capability that validates the next important
assumption**, evaluate it, then decide: retain, refine, replace, or discard.

| Do | Do not |
| --- | --- |
| A vertical slice through all the layers it touches | A complete subsystem, one layer at a time |
| Add a dependency in the increment that first *calls* it | Add it in the increment that first *mentions* it |
| Solve the case in front of you | Add a parameter, a registry or a plugin point for a second case that does not exist |
| Put the logic where the data already is | Move data to where you find the logic easier to write |
| Delete a prototype that did not work | Keep it because effort was spent |

**No speculative abstractions, frameworks, configuration systems or compatibility
layers.** A registry for two agents is a speculative abstraction; the typed
contract is what delivers the goal. If you are writing a base class with one
subclass, an interface with one implementation, or a config key with one value,
stop and inline it.

**One package, modules per component. One test suite.** Do not introduce a second
package, a second test runner, a monorepo layout, or a build step.

**Streaming-first.** Where a choice exists between doing the work in the engine's
SQL and doing it in Python, **the engine wins unless a measurement says
otherwise.** Minimize external code on the stream path.

**Plain view by default.** `CREATE MATERIALIZED VIEW` is the habit-forming
default and costs ~42 % disk for nothing when the view only feeds the layer above
it. Every view definition must state **which it is and what reads it**. Materialize
only where something is queried or joined from.

---

## 2. Consistency — the invariants you may not break

These are not style preferences. Breaking one produces a system that appears to
work and cannot be trusted.

**Structure**

- **One store.** Everything durable goes to the streaming engine as typed rows. No
  second database, no vector store, no checkpoint store, no file-backed agent
  memory, no cache that is not itself the evidence store.
- **The output topic is egress, not storage.** Nothing may be recoverable only
  from it.
- **The broker is addressed only through the Kafka wire protocol**, on both ends.
- **View layering holds:** flatten → signal → analytical. An analytical view never
  reads the flatten layer or the source directly.

**Control**

- **Orchestration is deterministic project code.** No model output determines
  control flow. Routing is an `if` you can read.
- **Agents propose; code validates and writes.** An agent never performs a side
  effect, never holds a credential, never calls a provider directly.
- **Nothing crosses an agent boundary except validated typed fields.** No
  free-text task field, no loose "observations" field, no recommended actions.
- **Deterministic escalation is independent of triage.** A `normal` from a model
  may not suppress a high-confidence match.

**Honesty of data**

- **Absence is not emptiness.** An unobserved layer is null and stays null; an
  observed-but-empty one is an empty array and is sent. A view that cannot tell
  those apart cannot tell "no DNS traffic" from "DNS traffic with no answers".
- **`stale`, `failed`, `missing` and `no_match` are four different things**, and
  a typed error is a fifth. Never collapse them, at any layer, for any reason.
- **Truncation is visible or it is a bug.**
- **A failed run is stored as a typed failure with no verdict**, and is emitted.
  Never a verdict, never a silent drop.
- **Unknown fields are quarantined, not coerced.** Input drift must surface.

**Reproducibility**

- **Every assessment records its versions** — model, prompt, schema, rendering,
  taxonomy, feed snapshot, aggregation, policy.
- **Replay validates against the version the assessment recorded**, never against
  current code. Historical schema classes are retained frozen; migrating old rows
  forward is forbidden.
- **Replay reads stored responses and never re-queries a live provider.**
- **Two copies of a version constant must be asserted equal by a test** — the SQL
  and the Python. Two copies that can drift are worse than none.

---

## 3. Decisions you may make, and decisions you must escalate

**Make these yourself:** naming, module layout inside the package, SQL formulation,
test structure, error message wording, whether a view is materialized, how to
factor a function.

**Stop and ask before:**

- adding any **runtime dependency**, or reaching for a framework;
- adding a **second store** of any kind, including a cache, a queue or a file;
- adding or changing an **enrichment source**;
- changing a **contract's** identity, provenance or relationship fields;
- editing the **taxonomy** — a revision is a new version module, never an edit;
- adding anything to the **agent contract**;
- widening the boundary toward **blocking, containment or remediation** — that is
  a change to the concept, not a diagram detail;
- adding an **HTTP surface**, a UI, or a second egress channel (including hosted
  tracing).

If you find yourself wanting one of these to make an increment work, the increment
is probably the wrong shape. Say so.

---

## 4. Working with unknowns

- **Do not invent a requirement to make a document look complete.** An open
  question stays open and stays written down.
- **State whether an unknown blocks the increment**, and if it does not, build
  around it under an explicitly stated assumption.
- **Do not infer a behaviour you could test.** Inference is exactly what produced
  the errors the project has already had to correct — measure it or mark it
  untested.
- **A discrepancy between two records is investigated, never papered over.** If
  two documents disagree, report it; do not quietly follow one.
- **Identifiers are never reused.** Check before allocating a new one.

---

## 5. Failure, measurement and honesty

- **Failed and inconclusive experiments are valid results.** Record what was
  measured and why it failed. Never rewrite or delete one.
- **Measure before generalizing.** "Measuring the mechanisms you thought of does
  not bound the mechanisms that exist" — a design once cost 740× the storage
  because a measurement of four mechanisms was generalized in one sentence.
- **Label maturity honestly** on anything you add, and keep the label current:

  | Label | Meaning |
  | --- | --- |
  | `stable` | Validated by tests **and** a recorded experiment or evaluation |
  | `experimental` | Code exists and is under evaluation |
  | `hypothesis` | Proposed, not validated — **never** read as accepted architecture |
  | `deferred` | Decided and recorded, deliberately not built yet |
  | `deprecated` | Previously used, since rejected or superseded |

  A deferred component that loses its label makes every other label a lie.
- **Never claim more than was demonstrated.** Determinism is not replayability.
  "The stages compose and cite" is not "the verdicts are right". If a property is
  blocked on the evaluation corpus, say the property is unmeasured.
- **Important knowledge goes in the repository**, not only in the conversation
  that produced it.

---

## 6. Recurring implementation traps

Concrete, and each has already cost this project something:

| Trap | Do this instead |
| --- | --- |
| Reading index `[0]` of a nested array | **Flatten.** In the worked DNS example the resolved address is at index 2 |
| A URI stored in a domain column | Store the **host part**, no scheme, path, query or port |
| An `ip:port` indicator joined against bare addresses | **Split the port into its own column** on the feed side — and keep it; it qualifies the match |
| A failed fetch leaving an empty table | Leave the **previous snapshot** in place and record the failure |
| A silent configuration default | **Fail at startup, naming the variable.** Empty and whitespace count as missing |
| A defaulted tenant | Same rule — a tenant that silently defaults is an isolation failure that looks like it is working |
| A secret in a URL reaching a log, a trace or a provenance record | **Redact the path segment** before anything is logged or stored |
| Catching an exception and continuing | Quarantine with a typed reason and the raw input **exactly as read**, and keep the stream running |
| Retrying schema-invalid model output forever, or "repairing" it with a second call | Bounded retries with the validation error fed back, then a typed failure. Repair calls are forbidden |
| Treating retrieved provider text as instruction | It is data. Isolate it, and **test the isolation** |
| Storing an assessment as an opaque JSON document | Typed columns, and **citations as join rows** |
| Adding a framework convenience because it is one flag away | Check it against the single-store, agents-propose and ephemeral-state rules first |

---

## 7. Definition of done for an increment

An increment is finished when **all** of these hold:

- [ ] The assumption it was built to validate is stated, and the result recorded —
      including if the result was negative or inconclusive.
- [ ] It is exercised by the one test suite, including its SQL, by execution
      against a throwaway instance.
- [ ] Every new view declares whether it is a view or a materialized view, and
      what reads it.
- [ ] Every new failure path is typed, stored and countable — nothing is dropped
      silently, and produced-versus-materialised counts reconcile.
- [ ] `stale` / `failed` / `missing` / `no_match` / typed error stay distinct end
      to end, including in whatever is rendered to an agent.
- [ ] Versions are recorded on every row that an assessment could cite, and
      duplicated constants are asserted equal.
- [ ] No new dependency, store, egress channel or contract field was added
      without an explicit decision.
- [ ] Maturity labels are present and accurate, and deferred things still say
      deferred.
- [ ] No credential appears in a prompt, a row, a log, a trace or the repository.
- [ ] The claim made about the increment is no stronger than what was
      demonstrated.
- [ ] The increment's **report is written and committed with it**, and the
      tracking files reflect it. The report is the handover the next session
      reads, so an increment with working code and no report is unfinished. If
      no runner launched the session, writing the report is not enough — see
      `prds/CONTEXT.md` §4, *Landing without the runner*, for the four other
      files nothing else will write.
