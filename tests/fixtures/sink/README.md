# The pinned output-message shape

`message-v1.json` is the JSON Schema of `helena.sink.OutputMessage` for
`helena.sink.MESSAGE_VERSION = "v1"` — `model_json_schema()` with every
`description` key removed, serialized with `indent=2, sort_keys=True` and one
trailing newline. `tests/test_sink.py::message_shape` is the generator and
`test_the_message_schema_is_what_it_was` compares it byte for byte.

**The prose is deliberately not pinned.** A `description` is a docstring or a
`#:` comment, and pinning those would make every clarification an interface
change — which teaches whoever hits it to regenerate the fixture, and a pin
people regenerate reflexively is not a pin. What is pinned is what
`docs/decisions/0036-the-output-message.md` §7 calls the interface: the field
set, the types and which fields are required.

## Why it exists

The output topic is an interface the moment anything consumes it
(`concept/03-architecture.md`, "The interfaces"). Unlike a prompt version or a
contract version, **no stored row records which message shape was emitted** — so
there is nothing in the engine that would catch a silent change, and no replay
that would fail. This file is the only thing standing between an edit to
`OutputMessage` and a consumer discovering it in production.

`docs/decisions/0036-the-output-message.md` §7 has the argument for why this is an
interface version rather than a frozen `vN` module.

## If the test that reads this fails

**Do not regenerate it to make the test pass.** A difference means the field set,
a field's type or a field's meaning changed, which is an **interface change**:

1. bump `helena.sink.MESSAGE_VERSION`;
2. write the new fixture beside this one as `message-v<N>.json` — the test asserts
   the file name matches the constant, so the old file stays where it is;
3. write the decision record that says what changed and what a consumer has to do.

The one case where regenerating *this* file is correct is a change to how the
schema is serialized — a Pydantic upgrade that reorders a key, say — where the
shape is identical and only the bytes moved. That is a change to what the file
means, so it comes with a note in the decision record rather than a quiet
rewrite.
