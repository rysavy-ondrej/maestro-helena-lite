"""Orchestration — deterministic project code around the agents.

Renders agent input, routes on the triage result and on independently escalating
evidence, enforces budgets, validates output, persists assessments including
typed failures, and replays from stored results. No model output determines
control flow; the routing is an `if` you can read, and deterministic escalation
is independent of triage.

An assessment is one function call over one versioned context snapshot. There is
no checkpoint store and no durable in-flight state outside the engine.

Maturity: deferred — placeholder. Built by the D6 Orchestration increments.
"""
