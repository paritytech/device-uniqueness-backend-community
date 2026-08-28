-- Widevine device dedup records — the PoUD Android device-uniqueness gate on
-- POST /api/v1/usernames (wire spec: envelope-wire-spec v1). One row per
-- pseudonymized physical device and namespace.
--
-- Privacy invariant: the raw widevineId is NEVER stored — `hmac` is
-- HMAC-SHA256(k_epoch, 'poud:v1' || namespace || widevineId), with the secret
-- key held in env/KMS (WIDEVINE_DEDUP_HMAC_KEYS, versioned epochs). Key
-- rotation looks rows up across every configured epoch and writes new rows
-- with the active one.
--
-- Lifecycle: PENDING is inserted in the same transaction as the username
-- reservation (the atomic reserve), the chain-writer marks it CONSUMED on
-- on-chain success, and a terminal claim failure DELETEs the PENDING row so
-- the device can claim again. CONSUMED rows are permanent.

CREATE TABLE widevine_devices (
    id              BIGSERIAL   PRIMARY KEY,
    -- 'widevine_l1' (measured L1) or 'widevine_l3' (GrapheneOS lane).
    -- The two namespaces are never merged.
    namespace       TEXT        NOT NULL,
    -- 32-byte HMAC-SHA256 of the device id (see header).
    hmac            BYTEA       NOT NULL,
    -- HMAC key epoch the value was computed with (e.g. 'v1').
    key_epoch       TEXT        NOT NULL,
    -- PENDING (reserved with a claim) -> CONSUMED (claim landed on-chain).
    -- Terminal claim failure deletes the PENDING row instead.
    status          TEXT        NOT NULL DEFAULT 'PENDING',
    -- The claim this record was reserved with.
    reservation_id  BIGINT      NOT NULL REFERENCES username_reservations(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One free registration per physical device per namespace: the atomic
    -- reserve races on this constraint.
    CONSTRAINT widevine_devices_device_key UNIQUE (namespace, hmac)
);

-- Chain-writer lookups on claim outcome (consume / release).
CREATE INDEX widevine_devices_reservation_idx
    ON widevine_devices (reservation_id);
