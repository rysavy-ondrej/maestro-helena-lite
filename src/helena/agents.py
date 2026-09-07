"""Agents — the Triage and Analyst runners over one versioned contract.

Two agents differing by model, not by framework. **The contract they exchange is
not here**: it is `helena.contracts`, a versioned package holding one frozen
request/result pair per version, because `docs/decisions/0008-version-registry.md`
retains historical agent schemas as frozen Pydantic classes and a class inside
this module would be edited every time the runner around it changed. This module
is what will *call* a model with a `helena.contracts.v1.AgentRequest` and turn
what comes back into an `AgentResult` or an `AgentFailure`.

The model client library is a technology-table entry and is deliberately absent
until the first increment that actually calls a model;
`tests/test_dependency_boundary.py` asserts its absence until then.

Nothing crosses the agent boundary except validated typed fields. An agent
proposes; deterministic code validates and writes. An agent never performs a side
effect, never holds a credential and never calls a provider directly.

Maturity: deferred — placeholder. Built by the D4/D5 agent increments.
"""
