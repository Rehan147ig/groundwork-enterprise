package notifications

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Interactive break-glass actions delivered through Slack. The action
// buttons are attached to notification messages; Slack posts the click
// payload to the runtime's /v1/security/slack/actions endpoint, which
// verifies the signature, the replay window, and the acting user's
// server-side role before touching any grant.
const (
	ActionApprove = "breakglass.approve"
	ActionReject  = "breakglass.reject"
	ActionRevoke  = "breakglass.revoke"
)

// actionPrefix is the callback prefix for break-glass interactive
// buttons. The callback ID carries the tenant and grant context.
const actionPrefix = "breakglass"

// ErrNotBreakGlassAction means the payload is not a break-glass
// interactive action (different app or message).
var ErrNotBreakGlassAction = errors.New("payload is not a break-glass action")

// ErrBadActionContext means the action value is malformed or missing.
var ErrBadActionContext = errors.New("malformed break-glass action context")

// ActionContext is the verified, parsed context of one interactive
// click. Everything here is untrusted input from Slack: the tenant and
// grant are re-checked against the store, and the user is re-checked
// against the server-side admin allowlist.
type ActionContext struct {
	Action   string // ActionApprove | ActionReject | ActionRevoke
	TenantID string
	GrantID  string
	UserID   string
	Channel  string
}

// SlackAction is the parsed interactive payload Slack posts to the
// actions endpoint (form field "payload", JSON).
type SlackAction struct {
	Type string `json:"type"`
	User struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Channel struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"channel"`
	CallbackID string `json:"callback_id"`
	Actions    []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	ResponseURL string `json:"response_url"`
}

// ParseSlackAction decodes the payload form value.
func ParseSlackAction(raw []byte) (SlackAction, error) {
	var a SlackAction
	if err := json.Unmarshal(raw, &a); err != nil {
		return SlackAction{}, fmt.Errorf("invalid slack action payload: %w", err)
	}
	return a, nil
}

// Context extracts the break-glass action context from the payload. The
// action value carries "<tenant_id>|<grant_id>"; the callback ID must
// match the same tenant/grant so cross-tenant confusion is impossible.
func (a SlackAction) Context() (ActionContext, error) {
	if a.User.ID == "" || len(a.Actions) == 0 {
		return ActionContext{}, ErrBadActionContext
	}
	act := a.Actions[0]
	if !strings.HasPrefix(act.ActionID, actionPrefix+".") {
		return ActionContext{}, ErrNotBreakGlassAction
	}
	tenantID, grantID, ok := strings.Cut(act.Value, "|")
	if !ok || tenantID == "" || grantID == "" {
		return ActionContext{}, ErrBadActionContext
	}
	if cb := strings.SplitN(a.CallbackID, ":", 3); len(cb) != 3 || cb[0] != actionPrefix || cb[1] != tenantID || cb[2] != grantID {
		return ActionContext{}, ErrBadActionContext
	}
	return ActionContext{
		Action:   act.ActionID,
		TenantID: tenantID,
		GrantID:  grantID,
		UserID:   a.User.ID,
		Channel:  a.Channel.ID,
	}, nil
}

// respondText is a minimal Slack interaction acknowledgment (shown as
// an ephemeral message to the clicking user).
func respondText(format string, args ...any) map[string]any {
	return map[string]any{"response_type": "ephemeral", "text": fmt.Sprintf(format, args...)}
}
