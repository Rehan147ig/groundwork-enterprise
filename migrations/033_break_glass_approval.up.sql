-- Break-glass 2-person approval flow (Milestone 5 notification delivery).
--
-- Widen the break-glass schema so a grant can wait in PENDING_APPROVAL
-- for a second admin (four-eyes), be rejected, and record notification
-- delivery failures as immutable evidence:
--
--   - break_glass_grants.status gains 'pending_approval' and 'rejected'
--     plus the approval columns (who must approve, who approved when);
--   - break_glass_events.event_type gains 'approved_by_admin1',
--     'approved_by_admin2', 'rejected' and 'notification_failed' so a
--     failed Slack/Teams delivery is never silently dropped;
--   - key_id/key_prefix become nullable: a pending grant has no minted
--     API key until the second admin activates it (fail closed — a
--     pending grant must not carry a live admin key).

ALTER TABLE break_glass_grants
    ADD COLUMN pending_approval_by     TEXT NOT NULL DEFAULT '',
    ADD COLUMN pending_approval_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN approver1               TEXT NOT NULL DEFAULT '',
    ADD COLUMN approver2               TEXT NOT NULL DEFAULT '',
    ADD COLUMN approved_by_admin1_at   TIMESTAMPTZ,
    ADD COLUMN approved_by_admin2_at   TIMESTAMPTZ,
    ALTER COLUMN key_id DROP NOT NULL,
    ALTER COLUMN key_prefix DROP NOT NULL,
    DROP CONSTRAINT break_glass_grants_status_check,
    ADD CONSTRAINT break_glass_grants_status_check
        CHECK (status IN ('pending_approval','active','expired','revoked','rejected'));

ALTER TABLE break_glass_events
    DROP CONSTRAINT break_glass_events_event_type_check,
    ADD CONSTRAINT break_glass_events_event_type_check
        CHECK (event_type IN
            ('opened','approved_by_admin1','approved_by_admin2',
             'expired','revoked','rejected','notification_failed'));