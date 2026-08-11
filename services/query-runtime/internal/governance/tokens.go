package governance

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------
// Delegation token authority.
//
// Delegation tokens are signed by a DEDICATED authority, separate from
// the end-user identity verifier (GROUNDWORK_JWT_*): their own issuer,
// audience, and signing key. The signing key is asymmetric (RS256) when
// a private key is configured, else a separate high-entropy HMAC secret
// (GROUNDWORK_DELEGATION_HS_SECRET) — never GROUNDWORK_JWT_HS_SECRET.
//
// Configuration:
//
//	GROUNDWORK_DELEGATION_ISSUER                token issuer (default groundwork-delegation)
//	GROUNDWORK_DELEGATION_AUDIENCE              token audience (default groundwork-agent-runs)
//	GROUNDWORK_DELEGATION_RS_PRIVATE_KEY        RSA private key PEM (preferred; RS256)
//	GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE   path to the RSA private key PEM
//	GROUNDWORK_DELEGATION_HS_SECRET             high-entropy HMAC secret (HS256 fallback)
//	GROUNDWORK_DELEGATION_HS_SECRET_PREVIOUS    previous HS secrets (space/comma
//	                                            separated) — verification only; signing
//	                                            always uses the current secret (rotation)
//	GROUNDWORK_DELEGATION_RS_PUBLIC_KEY_PREVIOUS previous RSA public keys (one or
//	                                            more PEM blocks) — verification only
//	GROUNDWORK_DELEGATION_ALGORITHMS            allow-list override (default: the
//	                                            configured method only)
//
// Tokens are short-lived (max runtime.MaxDelegationTTL) and carry
// issuer/audience/subject/jti/nbf/exp plus the delegation bindings
// (agent, version, delegator, subject, purpose, region, permitted
// actions digest). Run binding is enforced through the grant row: the
// server-generated run_id is stamped into delegated_authority_grants at
// run creation and validated at every action — the token is minted
// before any run exists and never carries a run id.
// ---------------------------------------------------------------------

// Claims is the signed delegation payload.
type Claims struct {
	TenantID               string   `json:"tenant_id"`
	AgentID                string   `json:"agent_id"`
	AgentVersionID         string   `json:"agent_version_id"`
	DelegatorPrincipalID   string   `json:"delegator_principal_id"`
	SubjectPrincipalID     string   `json:"subject_principal_id"`
	Purpose                string   `json:"purpose"`
	Region                 string   `json:"region"`
	PermittedActions       []string `json:"permitted_actions"`
	PermittedActionsDigest string   `json:"permitted_actions_digest"`
	jwt.RegisteredClaims

	// Phase 6: multi-agent chain bindings. Present only on
	// agent-delegated tokens (delegation_depth > 0); the verify path
	// requires the full set to be mutually consistent when any is set.
	ParentGrantID        string `json:"parent_grant_id,omitempty"`
	RootGrantID          string `json:"root_grant_id,omitempty"`
	DelegatorAgentID     string `json:"delegator_agent_id,omitempty"`
	DelegateeAgentID     string `json:"delegatee_agent_id,omitempty"`
	DelegationDepth      int    `json:"delegation_depth,omitempty"`
	AuthorityScopeDigest string `json:"authority_scope_digest,omitempty"`
	ParentScopeDigest    string `json:"parent_scope_digest,omitempty"`
	AttenuationDigest    string `json:"attenuation_digest,omitempty"`
}

// Authority mints and verifies delegation tokens.
type Authority struct {
	issuer   string
	audience string
	methods  []string
	now      func() time.Time

	// Signing key material (current).
	hsSecret     []byte
	rsPrivateKey *rsa.PrivateKey
	// Rotation keys (verification only).
	prevHSSecrets [][]byte
	prevRSPublic  []*rsa.PublicKey

	parser *jwt.Parser
}

// SetClock overrides the time source (tests).
func (a *Authority) SetClock(now func() time.Time) { a.now = now }

// BuildAuthority constructs the delegation authority from environment
// configuration. It returns an error (fatal at startup) when neither an
// RSA private key nor an HS secret is configured, so a runtime serving
// governed flows cannot silently start without a key.
func BuildAuthority() (*Authority, error) {
	issuer := envOr("GROUNDWORK_DELEGATION_ISSUER", "groundwork-delegation")
	audience := envOr("GROUNDWORK_DELEGATION_AUDIENCE", "groundwork-agent-runs")

	var hsSecret []byte
	if value := strings.TrimSpace(os.Getenv("GROUNDWORK_DELEGATION_HS_SECRET")); value != "" {
		if len(value) < 32 {
			return nil, errors.New("GROUNDWORK_DELEGATION_HS_SECRET must be at least 32 characters (high-entropy secret)")
		}
		hsSecret = []byte(value)
	}

	var rsPrivate *rsa.PrivateKey
	if inline := strings.TrimSpace(os.Getenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY")); inline != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(inline))
		if err != nil {
			return nil, fmt.Errorf("parse GROUNDWORK_DELEGATION_RS_PRIVATE_KEY: %w", err)
		}
		rsPrivate = key
	}
	if path := strings.TrimSpace(os.Getenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE")); path != "" && rsPrivate == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE: %w", err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE: %w", err)
		}
		rsPrivate = key
	}

	if rsPrivate == nil && hsSecret == nil {
		return nil, errors.New("no delegation signing key configured: set GROUNDWORK_DELEGATION_RS_PRIVATE_KEY(_FILE) (preferred) or GROUNDWORK_DELEGATION_HS_SECRET (>= 32 chars)")
	}

	prevHS, err := splitSecrets(os.Getenv("GROUNDWORK_DELEGATION_HS_SECRET_PREVIOUS"))
	if err != nil {
		return nil, err
	}
	prevRS, err := parsePublicKeyBlocks(os.Getenv("GROUNDWORK_DELEGATION_RS_PUBLIC_KEY_PREVIOUS"))
	if err != nil {
		return nil, err
	}

	methods := []string{"RS256"}
	if rsPrivate == nil {
		methods = []string{"HS256"}
	}
	if override := strings.TrimSpace(os.Getenv("GROUNDWORK_DELEGATION_ALGORITHMS")); override != "" {
		methods = splitCSV(override)
	}

	authority := &Authority{
		issuer:        issuer,
		audience:      audience,
		methods:       methods,
		now:           time.Now,
		hsSecret:      hsSecret,
		rsPrivateKey:  rsPrivate,
		prevHSSecrets: prevHS,
		prevRSPublic:  prevRS,
	}
	authority.parser = jwt.NewParser(
		jwt.WithValidMethods(methods),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(2*time.Second),
		// Dereference the field so SetClock (tests) takes effect.
		jwt.WithTimeFunc(func() time.Time { return authority.now() }),
	)
	return authority, nil
}

// Mint signs a delegation token for the grant's bindings. The token is
// returned to the caller exactly once; the service stores only the jti.
func (a *Authority) Mint(tenantID, agentID, agentVersionID, delegator, subject, purpose, region string, permitted []string, digest string, jti string, issuedAt, expiresAt time.Time) (string, error) {
	return a.mint(a.claimsFor(tenantID, agentID, agentVersionID, delegator, subject, purpose, region, permitted, digest, jti, issuedAt, expiresAt, Claims{}))
}

// MintChild signs a delegation token for an agent-delegated grant,
// carrying the full chain context (parent/root grant ids, depth, scope
// digests). The child scope is verified against the parent BEFORE mint
// by the service; the claims only bind what was validated.
func (a *Authority) MintChild(tenantID, agentID, agentVersionID, delegator, subject, purpose, region string, permitted []string, digest string, jti string, issuedAt, expiresAt time.Time, chain Claims) (string, error) {
	base := a.claimsFor(tenantID, agentID, agentVersionID, delegator, subject, purpose, region, permitted, digest, jti, issuedAt, expiresAt, chain)
	if base.DelegationDepth <= 0 {
		return "", fmt.Errorf("%w: child token requires delegation_depth > 0", runtime.ErrDelegationInvalid)
	}
	return a.mint(base)
}

func (a *Authority) claimsFor(tenantID, agentID, agentVersionID, delegator, subject, purpose, region string, permitted []string, digest string, jti string, issuedAt, expiresAt time.Time, chain Claims) Claims {
	return Claims{
		TenantID:               tenantID,
		AgentID:                agentID,
		AgentVersionID:         agentVersionID,
		DelegatorPrincipalID:   delegator,
		SubjectPrincipalID:     subject,
		Purpose:                purpose,
		Region:                 region,
		PermittedActions:       permitted,
		PermittedActionsDigest: digest,
		ParentGrantID:          chain.ParentGrantID,
		RootGrantID:            chain.RootGrantID,
		DelegatorAgentID:       chain.DelegatorAgentID,
		DelegateeAgentID:       chain.DelegateeAgentID,
		DelegationDepth:        chain.DelegationDepth,
		AuthorityScopeDigest:   chain.AuthorityScopeDigest,
		ParentScopeDigest:      chain.ParentScopeDigest,
		AttenuationDigest:      chain.AttenuationDigest,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Audience:  jwt.ClaimStrings{a.audience},
			Subject:   subject,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt.Add(-time.Second)),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
}

func (a *Authority) mint(claims Claims) (string, error) {
	if a.rsPrivateKey != nil {
		return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(a.rsPrivateKey)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.hsSecret)
}

// Verify validates the token (signature, algorithm allow-list, issuer,
// audience, expiry, not-before) and returns the claims. The current key
// is tried first, then every previous rotation key; jwt's HMAC
// verification compares signatures in constant time.
func (a *Authority) Verify(_ context.Context, token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Claims{}, runtime.ErrDelegationInvalid
	}
	claims := Claims{}
	if err := a.parseWith(token, &claims, a.currentKey); err == nil {
		return claims, a.validate(claims)
	}
	for _, secret := range a.prevHSSecrets {
		attempt := Claims{}
		if err := a.parseWith(token, &attempt, hmacKey(secret)); err == nil {
			return attempt, a.validate(attempt)
		}
	}
	for _, pub := range a.prevRSPublic {
		attempt := Claims{}
		if err := a.parseWith(token, &attempt, rsaKey(pub)); err == nil {
			return attempt, a.validate(attempt)
		}
	}
	return Claims{}, fmt.Errorf("%w: signature verification failed", runtime.ErrDelegationInvalid)
}

// validate enforces that every binding claim is present and non-empty
// (a signed token with missing bindings is still invalid). For
// agent-delegated tokens the chain claims must be mutually consistent.
func (a *Authority) validate(claims Claims) error {
	if claims.TenantID == "" || claims.AgentID == "" || claims.AgentVersionID == "" ||
		claims.DelegatorPrincipalID == "" || claims.SubjectPrincipalID == "" ||
		claims.Purpose == "" || claims.Region == "" || claims.ID == "" ||
		claims.PermittedActionsDigest == "" {
		return fmt.Errorf("%w: missing delegation binding claim", runtime.ErrDelegationInvalid)
	}
	if claims.DelegationDepth > 0 {
		if claims.ParentGrantID == "" || claims.RootGrantID == "" ||
			claims.DelegatorAgentID == "" || claims.DelegateeAgentID == "" ||
			claims.AuthorityScopeDigest == "" || claims.ParentScopeDigest == "" ||
			claims.AttenuationDigest == "" {
			return fmt.Errorf("%w: missing delegation chain claim", runtime.ErrDelegationInvalid)
		}
	}
	return nil
}

// parseWith runs the shared parser with a specific key function.
func (a *Authority) parseWith(token string, claims *Claims, kf jwt.Keyfunc) error {
	_, err := a.parser.ParseWithClaims(token, claims, kf)
	return err
}

func (a *Authority) currentKey(token *jwt.Token) (any, error) {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA:
		if a.rsPrivateKey == nil {
			return nil, errors.New("no RSA key configured")
		}
		return &a.rsPrivateKey.PublicKey, nil
	case *jwt.SigningMethodHMAC:
		if a.hsSecret == nil {
			return nil, errors.New("no HMAC secret configured")
		}
		return a.hsSecret, nil
	default:
		return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
	}
}

func hmacKey(secret []byte) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}
		return secret, nil
	}
}

func rsaKey(pub *rsa.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}
		return pub, nil
	}
}

// splitSecrets splits a space/comma-separated list of previous HMAC
// secrets, validating each is non-empty.
func splitSecrets(value string) ([][]byte, error) {
	var out [][]byte
	for _, part := range splitCSV(value) {
		if part != "" {
			out = append(out, []byte(part))
		}
	}
	return out, nil
}

// splitCSV splits a comma/space/newline-separated list.
func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parsePublicKeyBlocks parses one or more RSA public key PEM blocks.
func parsePublicKeyBlocks(value string) ([]*rsa.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var keys []*rsa.PublicKey
	rest := []byte(value)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("unexpected PEM block type %q in GROUNDWORK_DELEGATION_RS_PUBLIC_KEY_PREVIOUS", block.Type)
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("parse previous RSA public key: %w", err)
		}
		keys = append(keys, key)
		rest = remaining
	}
	if len(keys) == 0 {
		return nil, errors.New("no RSA public key PEM blocks found in GROUNDWORK_DELEGATION_RS_PUBLIC_KEY_PREVIOUS")
	}
	return keys, nil
}

func envOr(key, def string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return def
}
