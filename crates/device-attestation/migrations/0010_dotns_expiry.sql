-- When a claim's dotNS reservation signature dies.
--
-- `dotns_signed_at` is the client's timestamp; the gateway rejects the call
-- once `now > signed_at + DotnsGateway::MaxValiditySeconds`. That constant is
-- read from chain at intake (never configured) and stamped here as an absolute
-- instant, so every consumer compares against one value instead of re-deriving
-- it from a window it would have to fetch.
--
-- Advisory, not authoritative. The writer still enforces the LIVE window in
-- `check_dotns_submittable` before spending an extrinsic, so a runtime upgrade
-- that shortens `MaxValiditySeconds` between intake and submission is caught
-- there. This column exists so the QUEUE can schedule against the deadline:
-- without it a queued row's expiry is invisible until the writer picks it up,
-- which is exactly too late.
--
-- Since dotNS became the name authority an expired reservation is terminal for
-- the WHOLE claim, not just the name — `dotns_status = EXPIRED` abandons the
-- People half — so the cost of discovering it late is a registration the client
-- must start over, and only the client can re-sign.
--
--   NULL -> the request carried no dotns block, or the row predates this
--           migration. Deliberately ambiguous, matching `dotns_status` NULL.
--           There is no backfill: `dotns_signed_at` alone cannot be turned into
--           a deadline without the window that applied when it was signed.
ALTER TABLE username_reservations
    ADD COLUMN dotns_expires_at TIMESTAMPTZ;

-- Two scans hang off this column, both restricted to rows still in the queue:
-- the pre-emptive expiry sweep (deadline already passed) and the at-risk
-- promotion priority (deadline inside the current drain time). Both are
-- ordered by deadline, so it is the leading column.
CREATE INDEX username_reservations_queued_expiry_idx
    ON username_reservations (dotns_expires_at, created_at, id)
    WHERE status = 'QUEUED' AND dotns_expires_at IS NOT NULL;
