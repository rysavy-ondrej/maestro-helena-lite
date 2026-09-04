"""Agents — the versioned request/result contract, Triage and Analyst.

Two agents differing by model, not by framework. The contract — request, result
and the typed failure envelope — is the architectural commitment; the model
client library is a technology-table entry and is deliberately absent until the
first increment that actually calls a model.

Nothing crosses the agent boundary except validated typed fields. An agent
proposes; deterministic code validates and writes. An agent never performs a side
effect, never holds a credential and never calls a provider directly.

Maturity: deferred — placeholder. Built by the D4/D5 agent increments.
"""
