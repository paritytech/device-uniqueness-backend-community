-- Widevine device dedup records — the PoUD Android device-uniqueness gate on
-- POST /api/v1/usernames (wire spec: evidence-wire-spec v1). One row per
-- pseudonymized physical device, one pool. Measured Widevine L1 is a
-- protocol invariant enforced by the attested app, not a stored attribute.
--
-- Privacy invariants:
--   * The device id is NEVER stored — `device_hmac` is
--     HMAC-SHA256(k, 'poud:v1' || deviceId) with the secret key held in
--     env/KMS (WIDEVINE_DEDUP_HMAC_KEY), and deviceId is itself a
--     client-side SHA-256 of the raw Widevine id, which never leaves the
--     device.
--   * No permanent device→username link — `reservation_id` is set only
--     while a claim is in flight and cleared when it lands.
--
-- Lifecycle: PENDING is inserted in the same transaction as the username
-- reservation (the atomic reserve), the chain-writer marks it CONSUMED on
-- on-chain success (clearing reservation_id), and a terminal claim failure
-- DELETEs the PENDING row so the device can claim again. CONSUMED rows are
-- permanent.

CREATE TABLE widevine_devices (
    id              BIGSERIAL   PRIMARY KEY,
    -- 32-byte HMAC-SHA256 of the device pseudonym (see header).
    device_hmac     BYTEA       NOT NULL,
    -- PENDING (reserved with a claim) -> CONSUMED (claim landed on-chain).
    -- Terminal claim failure deletes the PENDING row instead.
    status          TEXT        NOT NULL DEFAULT 'PENDING',
    -- The claim this record was reserved with; NULL once CONSUMED.
    reservation_id  BIGINT      REFERENCES username_reservations(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One free registration per physical device: the atomic reserve races
    -- on this constraint.
    CONSTRAINT widevine_devices_device_key UNIQUE (device_hmac)
);

-- Chain-writer lookups on claim outcome (consume / release) — only
-- in-flight rows carry a reservation.
CREATE INDEX widevine_devices_reservation_idx
    ON widevine_devices (reservation_id)
    WHERE reservation_id IS NOT NULL;
