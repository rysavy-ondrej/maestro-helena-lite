-- 0001  The migration ledger: which numbered file has been applied, and how it went.
--
-- Applied by src/helena/migrations.py like any other file in this directory --
-- it is not bootstrapped from Python, because the engine's schema is project
-- source and splitting it between .sql files and a string constant would give
-- it two homes. When this table does not exist, nothing has been applied yet;
-- that is the empty state the runner starts from.
--
-- A table, not a view: it is state the runner writes with INSERT and reads back
-- over the PostgreSQL wire protocol. Nothing streams from it, and no view reads
-- it. `IF NOT EXISTS` makes a re-run safe after a crash between this DDL and
-- the ledger row that records it.
--
-- `status` is 'applied' or 'failed', and the two are never collapsed. RisingWave
-- has no transaction around DDL, so a file whose second statement failed has
-- left its first statement's objects behind: that is a half-migrated store, and
-- a row saying so is the only thing that makes it visible and countable. The
-- runner refuses to apply anything while a 'failed' row is present, so nothing
-- overwrites one by itself -- clearing it is a deliberate act by whoever
-- cleaned up after it.
--
-- `version` is the four-digit number in the file name, as an integer.
-- `checksum` is the sha256 of the file's bytes at the moment it was applied,
-- which is what makes a later edit to an applied file detectable.
CREATE TABLE IF NOT EXISTS helena_schema_migrations (
    version    INT PRIMARY KEY,
    name       VARCHAR NOT NULL,
    checksum   VARCHAR NOT NULL,
    status     VARCHAR NOT NULL,
    error      VARCHAR,
    applied_at TIMESTAMPTZ NOT NULL
);
