"""Sink — egress of every assessed context to the output topic.

A sink over a view joining the enriched context, the terminal verdict and the
cited evidence. Every terminal outcome is emitted exactly once, including `normal`
verdicts and typed failures, at-least-once delivery, over the Kafka wire protocol.

The output topic is egress, not storage: nothing may be recoverable only from it.
Emission is observable from the engine side — a count of rows the sink view
produced — because the broker discards its queue on restart.

Maturity: deferred — placeholder. Built by the D7 Emission increments.
"""
