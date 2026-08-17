package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------
// Enterprise OIDC identity (Phase 4): production identity via an
// external issuer (Entra ID, Okta, or any generic OIDC provider) using
// issuer discovery + JWKS validation.
//
// Guarantees:
//   - issuer discovery (.well-known/openid-configuration) at startup;
//     an unreachable or inconsistent issuer fails startup, not requests
//   - JWKS signature validation with strict kid selection
//   - strict issuer and audience checks
//   - allowed-algorithm allow-list (default RS256/PS256/ES256); "none"
//     and HS* are rejected
//   - expiry and not-before validation
//   - tenant mapping from TRUSTED configuration (a claim name +
//     optional allow-list); arbitrary claims never create tenants
//   - administrative role mapping only from configured role values
//   - canonical identity resolution from configured claim (default sub)
//   - any verification failure fails closed
//
// user_id/tenant_id/region/role fields in request bodies are NEVER
// consulted — tenant and region come from the API key context, identity
// from this verifier.
// ---------------------------------------------------------------------

// OIDCConfig is the trusted OIDC configuration. Every field comes from
// environment/deployment configuration — never from JWT claims.
type OIDCConfig struct {
	// Issuer is the exact issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0).
	// The token's "iss" must equal this exactly.
	Issuer string
	// ClientID is the Groundwork client id; used as the default audience.
	ClientID string
	// Audiences is the accepted audience set. When empty, ClientID is used.
	Audiences []string
	// Algorithms is the allowed signing algorithm allow-list. When
	// empty, RS256, PS256 and ES256 are allowed.
	Algorithms []string
	// JWKSURL overrides issuer discovery (discovery is used when empty).
	JWKSURL string
	// TenantClaim is the claim carrying the tenant mapping (default
	// "tid"). The claim value is only trusted when the issuer and
	// signature are verified.
	TenantClaim string
	// TenantAllowlist restricts the accepted tenant claim values.
	// When non-empty, a token whose tenant claim is outside the list is
	// rejected (fail closed).
	TenantAllowlist []string
	// AdminRolesClaim is the claim carrying role memberships (default
	// "roles"). Admin is granted ONLY when a configured admin role is
	// present.
	AdminRolesClaim string
	// AdminRoles is the configured set of administrative roles.
	AdminRoles []string
	// CanonicalClaim resolves the effective user id (default "sub").
	CanonicalClaim string
	// HTTPClient for discovery and JWKS fetches.
	HTTPClient *http.Client
}

type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// OIDCVerifier implements IdentityVerifier with strict OIDC validation.
type OIDCVerifier struct {
	cfg OIDCConfig

	mu        sync.RWMutex
	jwks      []jsonWebKey
	fetchedAt time.Time
	now       func() time.Time
	client    *http.Client
}

// NewOIDCVerifier performs issuer discovery immediately (fatal at
// startup on failure) and returns a ready verifier.
func NewOIDCVerifier(cfg OIDCConfig) (*OIDCVerifier, error) {
	cfg = normalizeOIDCConfig(cfg)
	// Fail closed: "sub" is the per-user subject identifier, never a
	// tenant identifier. Two Okta orgs (or any two providers) can issue
	// the same sub for different users; binding a tenant to sub would
	// let a foreign user land in this tenant.
	if strings.EqualFold(cfg.TenantClaim, "sub") {
		return nil, fmt.Errorf("tenant claim must not be %q: sub is the per-user subject, not a tenant identifier; configure a dedicated tenant claim (e.g. \"tid\" or a custom mapped claim)", "sub")
	}
	v := &OIDCVerifier{
		cfg:    cfg,
		now:    time.Now,
		client: cfg.HTTPClient,
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: 10 * time.Second}
	}
	if err := v.refreshJWKS(context.Background()); err != nil {
		return nil, fmt.Errorf("oidc issuer %q unreachable or inconsistent: %w", cfg.Issuer, err)
	}
	return v, nil
}

func normalizeOIDCConfig(cfg OIDCConfig) OIDCConfig {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if len(cfg.Audiences) == 0 && strings.TrimSpace(cfg.ClientID) != "" {
		cfg.Audiences = []string{strings.TrimSpace(cfg.ClientID)}
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "PS256", "ES256"}
	}
	if strings.TrimSpace(cfg.TenantClaim) == "" {
		cfg.TenantClaim = "tid"
	}
	if strings.TrimSpace(cfg.AdminRolesClaim) == "" {
		cfg.AdminRolesClaim = "roles"
	}
	if strings.TrimSpace(cfg.CanonicalClaim) == "" {
		cfg.CanonicalClaim = "sub"
	}
	seen := map[string]bool{}
	auds := make([]string, 0, len(cfg.Audiences))
	for _, a := range cfg.Audiences {
		a = strings.TrimSpace(a)
		if a != "" && !seen[a] {
			seen[a] = true
			auds = append(auds, a)
		}
	}
	cfg.Audiences = auds
	return cfg
}

// jwksURL resolves the JWKS endpoint: configured override or issuer
// discovery.
func (v *OIDCVerifier) jwksURL(ctx context.Context) (string, error) {
	if u := strings.TrimSpace(v.cfg.JWKSURL); u != "" {
		return u, nil
	}
	discovery := v.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned %s", resp.Status)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("discovery payload: %w", err)
	}
	if strings.TrimRight(doc.Issuer, "/") != v.cfg.Issuer {
		return "", fmt.Errorf("discovered issuer %q does not match configured issuer %q", doc.Issuer, v.cfg.Issuer)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery document has no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func (v *OIDCVerifier) refreshJWKS(ctx context.Context) error {
	u, err := v.jwksURL(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("jwks payload: %w", err)
	}
	if len(doc.Keys) == 0 {
		return errors.New("jwks contains no keys")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.jwks = doc.Keys
	v.fetchedAt = v.now()
	return nil
}

// keyFor returns the JWK for a kid, refreshing the cache when the kid
// is missing or the cache is stale. Any failure fails closed.
func (v *OIDCVerifier) keyFor(ctx context.Context, kid string) (jsonWebKey, error) {
	v.mu.RLock()
	keys, fetchedAt := v.jwks, v.fetchedAt
	v.mu.RUnlock()
	lookup := func(ks []jsonWebKey) (jsonWebKey, bool) {
		for _, k := range ks {
			if k.Kid == kid {
				return k, true
			}
		}
		return jsonWebKey{}, false
	}
	if key, ok := lookup(keys); ok && time.Since(fetchedAt) < 30*time.Minute {
		return key, nil
	}
	if err := v.refreshJWKS(ctx); err != nil {
		if key, ok := lookup(keys); ok {
			return key, nil // stale-while-error only for a known kid
		}
		return jsonWebKey{}, fmt.Errorf("jwks refresh failed: %w", err)
	}
	key, ok := lookup(v.snapshot())
	if !ok {
		return jsonWebKey{}, fmt.Errorf("no jwks key with kid %q", kid)
	}
	return key, nil
}

func (v *OIDCVerifier) snapshot() []jsonWebKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.jwks
}

// Verify validates the assertion token and returns the verified
// Identity. Failures return ErrIdentityInvalid (callers fail closed).
func (v *OIDCVerifier) Verify(ctx context.Context, token string) (Identity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Identity{}, ErrIdentityMissing
	}

	// Step 0: unverified header inspection — kid + alg.
	unverified, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	kid, _ := unverified.Header["kid"].(string)
	alg, _ := unverified.Header["alg"].(string)
	if kid == "" {
		return Identity{}, fmt.Errorf("%w: token has no kid", ErrIdentityInvalid)
	}
	if !allowedAlgorithm(v.cfg.Algorithms, alg) {
		return Identity{}, fmt.Errorf("%w: algorithm %q is not allowed", ErrIdentityInvalid, alg)
	}

	// Step 1: JWKS key selection (fail closed on any failure).
	jwk, err := v.keyFor(ctx, kid)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	key, err := jwk.PublicKey()
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}

	// Step 2: strict validation.
	claims := jwt.MapClaims{}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(v.cfg.Algorithms),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(10 * time.Second),
		jwt.WithTimeFunc(func() time.Time { return v.now() }),
	}
	// jwt v5.2's WithAudience takes a single audience; multi-audience is
	// checked explicitly below.
	if len(v.cfg.Audiences) == 1 {
		parserOpts = append(parserOpts, jwt.WithAudience(v.cfg.Audiences[0]))
	}
	parser := jwt.NewParser(parserOpts...)
	parsed, err := parser.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) { return key, nil })
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	if !parsed.Valid {
		return Identity{}, fmt.Errorf("%w: token is not valid", ErrIdentityInvalid)
	}
	if !audienceMatches(claims, v.cfg.Audiences) {
		return Identity{}, fmt.Errorf("%w: token audience is not in the configured set", ErrIdentityInvalid)
	}

	// Step 3: canonical identity resolution from configured claim.
	userID := claimString(claims, v.cfg.CanonicalClaim)
	if userID == "" {
		return Identity{}, fmt.Errorf("%w: canonical claim %q is empty", ErrIdentityInvalid, v.cfg.CanonicalClaim)
	}

	// Step 4: tenant mapping from trusted configuration. The value is
	// informational (tenant enforcement is the API key context); an
	// allow-listed deployment rejects unknown tenant values.
	mappedTenant := claimString(claims, v.cfg.TenantClaim)
	if mappedTenant == "" {
		return Identity{}, fmt.Errorf("%w: tenant claim %q is empty", ErrIdentityInvalid, v.cfg.TenantClaim)
	}
	if len(v.cfg.TenantAllowlist) > 0 && !containsString(v.cfg.TenantAllowlist, mappedTenant) {
		return Identity{}, fmt.Errorf("%w: tenant %q is not in the configured allow-list", ErrIdentityInvalid, mappedTenant)
	}

	// Step 5: administrative role mapping — admin ONLY from configured
	// role values. Never from arbitrary claims.
	roles := claimStrings(claims, v.cfg.AdminRolesClaim)
	admin := false
	if len(v.cfg.AdminRoles) > 0 {
		for _, configured := range v.cfg.AdminRoles {
			if containsString(roles, configured) {
				admin = true
				break
			}
		}
	}

	return Identity{
		UserID:        userID,
		Subject:       claimString(claims, "sub"),
		OID:           claimString(claims, "oid"),
		Email:         claimString(claims, "email"),
		Username:      claimString(claims, "preferred_username"),
		Issuer:        claimString(claims, "iss"),
		EmailVerified: claimBool(claims, "email_verified"),
		TenantID:      mappedTenant,
		Roles:         roles,
		Admin:         admin,
		Verified:      true,
	}, nil
}

// PublicKey converts the JWK to a crypto public key for the token's
// algorithm family.
func (k jsonWebKey) PublicKey() (any, error) {
	decode := func(s string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	}
	switch k.Kty {
	case "RSA":
		nBytes, err := decode(k.N)
		if err != nil {
			return nil, fmt.Errorf("bad RSA modulus: %w", err)
		}
		eBytes, err := decode(k.E)
		if err != nil {
			return nil, fmt.Errorf("bad RSA exponent: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		xBytes, err := decode(k.X)
		if err != nil {
			return nil, fmt.Errorf("bad EC x: %w", err)
		}
		yBytes, err := decode(k.Y)
		if err != nil {
			return nil, fmt.Errorf("bad EC y: %w", err)
		}
		curve := ecCurve(k.Crv)
		if curve == nil {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

func allowedAlgorithm(allowList []string, alg string) bool {
	for _, allowed := range allowList {
		if strings.EqualFold(allowed, alg) {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// audienceMatches reports whether the token's aud claim intersects the
// configured audience set (standard OIDC: at least one match).
func audienceMatches(claims jwt.MapClaims, configured []string) bool {
	if len(configured) == 0 {
		return true
	}
	var auds []string
	switch v := claims["aud"].(type) {
	case string:
		auds = []string{v}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				auds = append(auds, s)
			}
		}
	case []string:
		auds = v
	}
	for _, a := range auds {
		if containsString(configured, a) {
			return true
		}
	}
	return false
}

func claimStrings(claims jwt.MapClaims, key string) []string {
	var out []string
	switch v := claims[key].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	case string:
		for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// ecCurve maps OIDC JWK curve names to elliptic curves.
func ecCurve(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

// SetClock overrides the time source (tests).
func (v *OIDCVerifier) SetClock(now func() time.Time) { v.now = now }

// BuildOIDCVerifierFromEnv constructs the OIDC verifier from deployment
// configuration. Returns (nil, nil) when no issuer is configured.
//
//	GROUNDWORK_OIDC_ISSUER              required: issuer URL
//	GROUNDWORK_OIDC_CLIENT_ID           required: client/application id
//	GROUNDWORK_OIDC_AUDIENCE            optional: space/comma audiences (defaults to client id)
//	GROUNDWORK_OIDC_JWKS_URL            optional: override issuer discovery
//	GROUNDWORK_OIDC_ALGORITHMS          optional: allow-list (default RS256,PS256,ES256)
//	GROUNDWORK_OIDC_TENANT_CLAIM        optional: tenant claim (default tid)
//	GROUNDWORK_OIDC_TENANT_ALLOWLIST    optional: accepted tenant values (comma-separated)
//	GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM   optional: roles claim (default roles)
//	GROUNDWORK_OIDC_ADMIN_ROLES         optional: comma-separated admin roles
//	GROUNDWORK_OIDC_CANONICAL_CLAIM     optional: canonical user-id claim (default sub)
func BuildOIDCVerifierFromEnv() (*OIDCVerifier, error) {
	issuer := strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_ISSUER"))
	if issuer == "" {
		return nil, nil
	}
	cfg := OIDCConfig{
		Issuer:          issuer,
		ClientID:        strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_CLIENT_ID")),
		JWKSURL:         strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_JWKS_URL")),
		TenantAllowlist: splitEnvList(os.Getenv("GROUNDWORK_OIDC_TENANT_ALLOWLIST")),
		AdminRoles:      splitEnvList(os.Getenv("GROUNDWORK_OIDC_ADMIN_ROLES")),
		AdminRolesClaim: strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM")),
		TenantClaim:     strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_TENANT_CLAIM")),
		CanonicalClaim:  strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_CANONICAL_CLAIM")),
	}
	if audience := strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_AUDIENCE")); audience != "" {
		cfg.Audiences = splitEnvList(audience)
	}
	if algorithms := strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_ALGORITHMS")); algorithms != "" {
		cfg.Algorithms = splitEnvList(algorithms)
	}
	if cfg.ClientID == "" && len(cfg.Audiences) == 0 {
		return nil, errors.New("GROUNDWORK_OIDC_ISSUER set but neither GROUNDWORK_OIDC_CLIENT_ID nor GROUNDWORK_OIDC_AUDIENCE is configured")
	}
	if err := urlParseCheck(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("GROUNDWORK_OIDC_ISSUER is not a valid URL: %w", err)
	}
	// Audience values must be syntactically valid client/app identifiers —
	// an empty or malformed audience silently widens acceptance.
	for _, a := range cfg.Audiences {
		if strings.TrimSpace(a) == "" {
			return nil, errors.New("GROUNDWORK_OIDC_AUDIENCE contains an empty value")
		}
		if len(a) > 1024 {
			return nil, errors.New("GROUNDWORK_OIDC_AUDIENCE value exceeds 1024 characters")
		}
	}
	// Tenant allow-list without an explicit tenant claim would silently
	// map the default claim; require the mapping to be explicit so a
	// deployment cannot accidentally gate on the wrong claim.
	if len(cfg.TenantAllowlist) > 0 && strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_TENANT_CLAIM")) == "" {
		return nil, errors.New("GROUNDWORK_OIDC_TENANT_ALLOWLIST set without GROUNDWORK_OIDC_TENANT_CLAIM: tenant mapping must be explicit when allow-listing tenant values")
	}
	// Admin-role mapping without an explicit roles claim would silently
	// default to the "roles" claim; require explicitness the same way.
	if len(cfg.AdminRoles) > 0 && strings.TrimSpace(os.Getenv("GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM")) == "" {
		return nil, errors.New("GROUNDWORK_OIDC_ADMIN_ROLES set without GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM: the roles claim must be explicit when mapping admin roles")
	}
	return NewOIDCVerifier(cfg)
}

func urlParseCheck(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("issuer must be an https URL")
	}
	return nil
}

func splitEnvList(value string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		part = strings.TrimSpace(part)
		if part != "" && !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}
