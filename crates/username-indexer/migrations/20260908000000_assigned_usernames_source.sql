-- Which chain a projection row's name came from.
--
-- Asset Hub's `DotnsGateway` is the name authority. People `Resources::Consumers`
-- is legacy: it still carries username bytes for accounts registered before the
-- cutover, and those rows are never re-registered, so the projection has to
-- serve both populations at once. There is no backfill in either direction —
-- a People-era name cannot be conjured onto the gateway, and the gateway's
-- history cannot be replayed into `Consumers`.
--
-- Precedence is fixed and one-way: `asset-hub` wins. Both ingests key on
-- `account_id`, so an account that appears in both is one that registered on
-- People and later reserved on the gateway; the gateway's answer is the
-- authoritative one and the People pass must not overwrite it. That rule lives
-- in the upsert's WHERE clause, not here, but this column is what makes it
-- expressible.
--
-- DEFAULT 'people' is deliberate for the backfill of existing rows: every row
-- that predates this column was written by the People ingest, which is exactly
-- what the default records. New rows always pass an explicit value.
ALTER TABLE assigned_usernames
    ADD COLUMN source TEXT NOT NULL DEFAULT 'people'
    CONSTRAINT assigned_usernames_source_known
    CHECK (source IN ('people', 'asset-hub'));

-- The two ingests advance independently, so the Asset Hub half needs its own
-- checkpoint. Splitting it out rather than reusing `last_finalized_number`
-- keeps the People pass's crash-safety argument intact: each pass commits its
-- own rows and its own cursor in one transaction, and neither can drag the
-- other backwards.
--
-- Nullable for the same reason `genesis_hash` is: no Asset Hub block number can
-- be reconstructed for a projection built before this column existed. NULL
-- means "the gateway ingest has not run yet", which `ensure_seeded` reads as
-- "scan LiteLabelOwner from scratch" — cheap, because that map is small next to
-- the People consumer set, and correct, because it is a complete snapshot
-- rather than a replay.
ALTER TABLE sync_state
    ADD COLUMN ah_last_finalized_number BIGINT
        CONSTRAINT sync_state_ah_number_valid
        CHECK (ah_last_finalized_number IS NULL OR ah_last_finalized_number >= 0),
    ADD COLUMN ah_last_finalized_hash BYTEA
        CONSTRAINT sync_state_ah_hash_len
        CHECK (ah_last_finalized_hash IS NULL OR octet_length(ah_last_finalized_hash) = 32),
    ADD COLUMN ah_genesis_hash BYTEA
        CONSTRAINT sync_state_ah_genesis_hash_len
        CHECK (ah_genesis_hash IS NULL OR octet_length(ah_genesis_hash) = 32);

-- The People pass reads this to decide whether it may touch a row at all, on
-- every affected account. Partial, because the gateway population is the small
-- half and the People pass only ever asks about the rows it would overwrite.
CREATE INDEX assigned_usernames_asset_hub_idx
    ON assigned_usernames (account_id)
    WHERE source = 'asset-hub';
