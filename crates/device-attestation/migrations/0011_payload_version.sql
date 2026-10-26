-- The signed-payload format the claim declared
ALTER TABLE username_reservations
    ADD COLUMN payload_version SMALLINT NOT NULL DEFAULT 0;
