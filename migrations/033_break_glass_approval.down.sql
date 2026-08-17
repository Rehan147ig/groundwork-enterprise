-- Reverse 033: restore the original break-glass CHECK domains and
-- drop the approval columns. key_id/key_prefix return to NOT NULL
-- (active grants always minted a key).

ALTER TABLE break_glass_events
    DROP CONSTRAINT break_glass_events_event_type_check,
    ADD CONSTRAINT break_glass_events_event_type_check
        CHECK (event_type IN ('opened','expired','revoked'));

ALTER TABLE break_glass_grants
    DROP CONSTRAINT break_glass_grants_status_check,
    ADD CONSTRAINT break_glass_grants_status_check
        CHECK (status IN ('active','expired','revoked')),
    ALTER COLUMN key_id SET NOT NULL,
    ALTER COLUMN key_prefix SET NOT NULL,
    DROP COLUMN pending_approval_by,
    DROP COLUMN pending_approval_reason,
    DROP COLUMN approver1,
    DROP COLUMN approver2,
    DROP COLUMN approved_by_admin1_at,
    DROP COLUMN approved_by_admin2_at;