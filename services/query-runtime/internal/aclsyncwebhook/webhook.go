// Package webhook implements real-time identity-provider change
// ingestion for the ACL sync pipeline: Microsoft Entra ID lifecycle
// notifications and Okta system-log webhooks are signature-verified,
// parsed into permission-change events, applied to the relationship tuple
// sink, and immediately invalidate the L1 policy cache.
//
// This closes the CISO requirement: when an employee leaves or changes
// teams, their AI access revokes in under a second — no polling
// interval, no re-index, no manual step.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"groundwork/query-runtime/internal/aclsync"
)

// Signature headers used by each provider.
const (
	EntraSignatureHeader = "X-Ms-Connector-Sig"
	OktaSignatureHeader  = "X-Okta-Signature"
)

// ErrSignatureInvalid reports a failed webhook signature check. The
// request must be rejected (fail closed).
var ErrSignatureInvalid = errors.New("webhook signature invalid")

// ErrWebhookUnavailable reports a receiver without a configured secret
// or sink.
var ErrWebhookUnavailable = errors.New("acl sync webhook unavailable")

// Event is one normalized permission change from a provider.
type Event struct {
	Provider string
	// Type is one of ChangeAddGroupMember, ChangeRevokeGroupMember,
	// ChangeTerminateUser (termination revokes every grant the user had).
	Type    aclsync.ChangeType
	UserID  string
	GroupID string
}

// NewGroupMemberEvent builds a membership-change event.
func NewGroupMemberEvent(provider string, add bool, userID, groupID string) Event {
	kind := aclsync.ChangeRevokeGroupMember
	if add {
		kind = aclsync.ChangeAddGroupMember
	}
	return Event{Provider: provider, Type: kind, UserID: userID, GroupID: groupID}
}

// NewTerminationEvent builds a user-termination event.
func NewTerminationEvent(provider, userID string) Event {
	return Event{Provider: provider, Type: aclsync.ChangeTerminateUser, UserID: userID}
}

// ---- signature verification ----

// VerifyEntraSignature verifies an Entra lifecycle notification
// signature (X-Ms-Connector-Sig, hex HMAC-SHA256 of the raw body with
// the app's client secret). Constant-time compare; missing header fails
// closed.
func VerifyEntraSignature(secret string, body []byte, signature string) bool {
	return verifyHMAC(secret, body, signature, false)
}

// VerifyOktaSignature verifies an Okta system-log signature
// (X-Okta-Signature, base64 HMAC-SHA256 of the raw body with the
// shared secret).
func VerifyOktaSignature(secret string, body []byte, signature string) bool {
	return verifyHMAC(secret, body, signature, true)
}

func verifyHMAC(secret string, body []byte, signature string, base64Encoded bool) bool {
	if secret == "" || strings.TrimSpace(signature) == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	var given []byte
	var err error
	if base64Encoded {
		given, err = base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	} else {
		given, err = hex.DecodeString(strings.TrimSpace(signature))
	}
	if err != nil {
		return false
	}
	return hmac.Equal(given, expected)
}

// ---- Entra ID lifecycle notification parser ----

// EntraNotification is the Azure lifecycle-notifications envelope.
type EntraNotification struct {
	Value []EntraEvent `json:"value"`
}

// EntraEvent is one lifecycle entry.
type EntraEvent struct {
	EventName string `json:"eventName"`
	Data      struct {
		MemberID string `json:"memberId"`
		GroupID  string `json:"groupId"`
		UserID   string `json:"userId"`
	} `json:"data,omitempty"`
	MemberID string `json:"memberId,omitempty"`
	GroupID  string `json:"groupId,omitempty"`
}

// ParseEntraEvents converts a lifecycle-notification body into
// normalized events. Events that carry no permission delta (user
// created, group created) are dropped.
func ParseEntraEvents(body []byte) ([]Event, error) {
	var notification EntraNotification
	if err := json.Unmarshal(body, &notification); err != nil {
		return nil, fmt.Errorf("entra webhook: %w", err)
	}
	var out []Event
	for _, ev := range notification.Value {
		name := strings.ToLower(strings.TrimSpace(ev.EventName))
		memberID := firstNonEmpty(ev.Data.MemberID, ev.Data.UserID, ev.MemberID)
		groupID := firstNonEmpty(ev.Data.GroupID, ev.GroupID)
		switch name {
		case "userdeleted", "userpermanentdeleted", "usermoved", "usermovedcompany", "userremovedfromcompany":
			if memberID != "" {
				out = append(out, NewTerminationEvent("entra", memberID))
			}
		case "groupmemberadded", "groupmembershipadded", "groupmemberadd":
			if memberID != "" && groupID != "" {
				out = append(out, NewGroupMemberEvent("entra", true, memberID, groupID))
			}
		case "groupmemberremoved", "groupmembershipremoved", "groupmemberremove":
			if memberID != "" && groupID != "" {
				out = append(out, NewGroupMemberEvent("entra", false, memberID, groupID))
			}
		case "groupuseradded", "groupuserremoved":
			if memberID != "" && groupID != "" {
				out = append(out, NewGroupMemberEvent("entra", name == "groupuseradded", memberID, groupID))
			}
		}
	}
	return out, nil
}

// ---- Okta system-log parser ----

// OktaLog is the system-log envelope.
type OktaLog struct {
	Events []OktaLogEvent `json:"events"`
}

// OktaLogEvent is one Okta system-log entry.
type OktaLogEvent struct {
	EventType string `json:"eventType"`
	Target    []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"target"`
}

// ParseOktaEvents converts an Okta system-log body into normalized
// events. Supported event types: group.user_membership.add/.remove,
// user.account.terminate/.suspend, user.lifecycle.deactivate.
func ParseOktaEvents(body []byte) ([]Event, error) {
	var log OktaLog
	if err := json.Unmarshal(body, &log); err != nil {
		return nil, fmt.Errorf("okta webhook: %w", err)
	}
	var out []Event
	for _, ev := range log.Events {
		eventType := strings.ToLower(strings.TrimSpace(ev.EventType))
		var userID, groupID string
		for _, t := range ev.Target {
			switch t.Type {
			case "User", "user":
				userID = t.ID
			case "UserGroup", "user_group", "Group":
				groupID = t.ID
			}
		}
		switch {
		case eventType == "group.user_membership.add":
			if userID != "" && groupID != "" {
				out = append(out, NewGroupMemberEvent("okta", true, userID, groupID))
			}
		case eventType == "group.user_membership.remove":
			if userID != "" && groupID != "" {
				out = append(out, NewGroupMemberEvent("okta", false, userID, groupID))
			}
		case strings.Contains(eventType, "user.account.terminate"),
			strings.Contains(eventType, "user.account.suspend"),
			strings.Contains(eventType, "user.lifecycle.deactivate"):
			if userID != "" {
				out = append(out, NewTerminationEvent("okta", userID))
			}
		}
	}
	return out, nil
}

// ---- receiver ----

// GroupUpdater keeps the L1 group directory current as membership
// events apply (implemented by policy.MemoryGroups in production).
type GroupUpdater interface {
	SetMembership(ctx context.Context, tenantID, userID, groupID string, member bool) error
}

// CacheInvalidator drops stale L1 policy-cache entries as privilege
// changes apply, so revocation takes effect on the next request
// (implemented by policy.PolicyCache adapters).
type CacheInvalidator interface {
	InvalidateUser(tenantID, userID string)
	InvalidateTenant(tenantID string)
}

// Receiver applies provider events to the tuple sink and invalidates
// the L1 policy cache.
type Receiver struct {
	Sink   aclsync.TupleSink
	Groups GroupUpdater // optional L1 group directory
	// Invalidator, when set, drops L1 cache entries for affected users
	// (terminations, revocations) or the whole tenant (membership
	// changes, whose member sets are not tracked in cache keys).
	Invalidator CacheInvalidator
	// OnApplied, when set, is invoked with the count applied per tenant.
	OnApplied func(tenantID string, applied int)
	// OnError, when set, is invoked on apply failures.
	OnError func(tenantID string, err error)
}

// Apply applies events for one tenant. Membership additions write
// tuples; removals and terminations delete tuples and invalidate the
// L1 cache (via the Groups updater and sink deletes). Idempotent:
// re-applying the same events is a no-op at the sink.
func (r *Receiver) Apply(ctx context.Context, tenantID string, events []Event) error {
	if r == nil || r.Sink == nil {
		return ErrWebhookUnavailable
	}
	var writes, deletes []aclsync.Tuple
	for _, ev := range events {
		if ev.UserID == "" {
			continue
		}
		switch ev.Type {
		case aclsync.ChangeAddGroupMember:
			if ev.GroupID != "" {
				writes = append(writes, aclsync.Tuple{User: "user:" + ev.UserID, Relation: "member", Object: "group:" + ev.GroupID})
			}
			if r.Groups != nil {
				_ = r.Groups.SetMembership(ctx, tenantID, ev.UserID, ev.GroupID, true)
			}
			// A newly granted member may hold cached denials; drop them.
			if r.Invalidator != nil {
				r.Invalidator.InvalidateUser(tenantID, ev.UserID)
			}
		case aclsync.ChangeRevokeGroupMember:
			if ev.GroupID != "" {
				deletes = append(deletes, aclsync.Tuple{User: "user:" + ev.UserID, Relation: "member", Object: "group:" + ev.GroupID})
			}
			if r.Groups != nil {
				_ = r.Groups.SetMembership(ctx, tenantID, ev.UserID, ev.GroupID, false)
			}
			// Revocation must take effect immediately: drop every cached
			// decision for this user.
			if r.Invalidator != nil {
				r.Invalidator.InvalidateUser(tenantID, ev.UserID)
			}
		case aclsync.ChangeTerminateUser:
			termination, err := r.terminationTuples(ctx, tenantID, ev.UserID)
			if err != nil {
				if r.OnError != nil {
					r.OnError(tenantID, err)
				}
				return err
			}
			deletes = append(deletes, termination...)
			if r.Invalidator != nil {
				r.Invalidator.InvalidateUser(tenantID, ev.UserID)
			}
		}
	}
	if len(writes) > 0 {
		if err := r.Sink.WriteTuples(ctx, tenantID, writes); err != nil {
			if r.OnError != nil {
				r.OnError(tenantID, err)
			}
			return err
		}
	}
	if len(deletes) > 0 {
		if err := r.Sink.DeleteTuples(ctx, tenantID, deletes); err != nil {
			if r.OnError != nil {
				r.OnError(tenantID, err)
			}
			return err
		}
	}
	if r.OnApplied != nil {
		r.OnApplied(tenantID, len(writes)+len(deletes))
	}
	return nil
}

// terminationTuples collects every tuple that grants the terminated
// user access (direct grants + memberships), so termination revokes
// all of them at the sink.
func (r *Receiver) terminationTuples(ctx context.Context, tenantID, userID string) ([]aclsync.Tuple, error) {
	existing, err := r.Sink.ListTuples(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	subject := "user:" + userID
	var out []aclsync.Tuple
	for _, t := range existing {
		if t.User == subject {
			out = append(out, t)
		}
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
