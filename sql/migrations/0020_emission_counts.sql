-- 0020  The engine-side emission counter.
--
-- `concept/03-architecture.md`:
--
--   *"**Emission must be observable from the engine side** -- a count of rows the
--   sink view produced -- because the broker discards its queue on restart, so a
--   message emitted with no consumer attached is simply gone and nothing counts
--   it. Otherwise 'nothing arrived' cannot be told apart from 'nothing was
--   assessed'."*
--
-- This file is that count, and it is in the engine rather than only in Python
-- for the reason the sentence gives. The broker keeps nothing: measured against
-- the pinned blink 0.2.0, a topic drained once is empty again and a topic nobody
-- drained is empty after a restart. So when a consumer reports that nothing
-- arrived, the only surviving record of how many messages there were to arrive
-- is on this side of the wire -- and it has to be askable with plain SQL, by an
-- operator who is not running the emitter, or it does not answer the question.
--
--   SELECT * FROM helena_analytical_emission_counts;
--
--   0 rows            nothing was assessed
--   pending = 12      twelve messages existed; if none arrived, they are gone
--
-- The same shape as `helena_ingest_counts` in 0004 and the quarantine counter in
-- 0003, and the same reason: a counter over a relation, read as a number rather
-- than joined from.
--
-- ## The grain is messages, not rows
--
-- `concept/03` says *"a count of rows the sink view produced"*, and the honest
-- reading of that is the count at the grain the consumer reconciles against.
-- `helena_analytical_sink`'s own grain is (terminal run x entity x source), and
-- measured over the layers capture one assessed context is 41 rows and one
-- message. Counting rows would make "one message arrived and 40 did not" the
-- natural reading of a topic that carried exactly what it should have, and
-- "nothing arrived" impossible to tell from "one message arrived" -- the precise
-- confusion the count exists to prevent. `count(DISTINCT assessment_id)` is one
-- per message (`concept/03`: *"one JSON message per assessed context"*), and
-- `helena_analytical_sink` has already chosen the terminal run of each pass, so
-- an escalated context counts once and under the analyst's identifier.
--
-- ## It is not a record of what was emitted
--
-- This counts what the store says is *emittable*, which is the only thing the
-- engine can honestly count. Nothing here records that a message was produced,
-- and that is deliberate rather than missing: delivery is at-least-once and a
-- re-run legitimately emits the same assessment again, so a ledger of what was
-- emitted would be a table whose only use is suppressing a duplicate the
-- contract says the consumer removes -- and, worse, the first step toward an
-- exactly-once this project does not attempt
-- (`docs/decisions/0037-at-least-once-emission.md` §3). The sink stays egress:
-- it reads the store and writes to the broker, and writes nothing back.


-- helena_analytical_emission_counts: how many messages this deployment has to emit.
--
-- Layer:    analytical. A counter over an analytical view, the way
--           helena_ingest_counts is a counter over the source table.
-- Object:   VIEW (plain). A count over a view; nothing streams or joins from it,
--           so materializing it would be disk for a number -- and it could not be
--           materialized in any case, because helena_analytical_sink cannot be
--           the source of a streaming job (0019's head has the measurement).
-- Reads:    helena_analytical_sink
-- Read by:  src/helena/sink.py -- `SinkStore.pending`, which is the number
--           `helena.sink.emit` reconciles what it produced against -- an operator
--           asking the engine directly (docs/runbook.md §12),
--           helena_analytical_pipeline_reconciliation (sql/migrations/0021,
--           which is this count beside the contexts and assessments behind it,
--           rather than a second count of the sink view), and
--           tests/test_sink.py.
CREATE VIEW helena_analytical_emission_counts AS
SELECT tenant,
       sensor,
       count(DISTINCT assessment_id) AS pending
FROM   helena_analytical_sink
GROUP BY tenant, sensor;
