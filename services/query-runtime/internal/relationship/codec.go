package relationship

import (
	"fmt"
	"strings"
)

// permissionToRelation maps neutral permissions onto storage relations.
// It is the single place the "view" -> "viewer" alias lives; the rest are
// identity mappings. Unknown permissions fall through unchanged so every
// caller of CheckRelation-style surfaces fails closed via the backend
// (unknown relations are never granted).
func PermissionToRelation(p string) string {
	if p == PermissionView {
		return RelationViewer
	}
	return p
}

// RelationToPermission is the inverse of PermissionToRelation.
func RelationToPermission(r string) string {
	if r == RelationViewer {
		return PermissionView
	}
	return r
}

// EncodeSubject renders a subject in tuple format:
//
//	user  -> "user:<id>"
//	group -> "group:<id>#member" (or "group:<id>" when Relation is empty)
//	other -> "<type>:<id>"
//
// IDs are never validated here beyond non-emptiness — callers pass
// verified identifiers. A principal ID that itself contains "principal:"
// (legacy prefix) round-trips losslessly because the format splits on the
// FIRST colon only.
func EncodeSubject(s SubjectRef) string {
	switch s.Type {
	case TypeGroup:
		if s.Relation != "" {
			return TypeGroup + ":" + s.ID + "#" + s.Relation
		}
		return TypeGroup + ":" + s.ID
	default:
		return s.Type + ":" + s.ID
	}
}

// EncodeObject renders a resource in tuple format:
// "<type>:<id>". Composite IDs (tool_action "<toolID>:<action>") are
// embedded verbatim; backends match on the full "type:id" string.
func EncodeObject(r ResourceRef) string {
	return r.Type + ":" + r.ID
}

// ParseSubject parses "user:<id>", "group:<id>#member" (or
// "group:<id>"), and any "<type>:<id>" — mirroring EncodeSubject.
func ParseSubject(s string) (SubjectRef, error) {
	typ, id, rel, err := splitTupleUser(s)
	if err != nil {
		return SubjectRef{}, err
	}
	return SubjectRef{Type: typ, ID: id, Relation: rel}, nil
}

// ParseObject parses "<type>:<id>", splitting on the first colon
// so composite IDs round-trip.
func ParseObject(s string) (ResourceRef, error) {
	typ, id, err := splitTupleObject(s)
	if err != nil {
		return ResourceRef{}, err
	}
	return ResourceRef{Type: typ, ID: id}, nil
}

func splitTupleUser(s string) (typ, id, rel string, err error) {
	base, userset, hasUserset := strings.Cut(s, "#")
	if hasUserset && userset == "" {
		return "", "", "", fmt.Errorf("relationship: empty userset relation in %q", s)
	}
	typ, id, err = splitTupleObject(base)
	if err != nil {
		return "", "", "", err
	}
	if hasUserset {
		rel = userset
	}
	return typ, id, rel, nil
}

func splitTupleObject(s string) (typ, id string, err error) {
	typ, id, ok := strings.Cut(s, ":")
	if !ok || typ == "" || id == "" {
		return "", "", fmt.Errorf("relationship: malformed tuple reference %q (want <type>:<id>)", s)
	}
	if strings.Contains(typ, ":") || strings.ContainsAny(typ, " \t\r\n#") {
		return "", "", fmt.Errorf("relationship: malformed tuple type in %q", s)
	}
	return typ, id, nil
}

// ValidateSubject reports whether a subject is well-formed enough to
// send to any backend. Empty components are rejected (deny, per the
// fail-closed rule); composite IDs (tool_action) are only meaningful on
// resources and are allowed in IDs.
func ValidateSubject(s SubjectRef) error {
	if s.Type == "" || s.ID == "" {
		return fmt.Errorf("relationship: subject type and id are required")
	}
	return nil
}

// ValidateResource reports whether a resource is well-formed.
func ValidateResource(r ResourceRef) error {
	if r.Type == "" || r.ID == "" {
		return fmt.Errorf("relationship: resource type and id are required")
	}
	return nil
}

// EscapeID converts a raw identifier into a form valid as a SpiceDB
// object ID. SpiceDB validates object IDs against
// ^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$ — colons, tildes, dots, and other
// punctuation are rejected at the server. The scheme passes through the
// common identifier alphabet [a-zA-Z0-9_-] (UUIDs, kebab/snake case)
// unchanged and hex-escapes every other byte as "=" + two uppercase hex
// digits, so the result is reversible, contains only SpiceDB-valid
// characters, and grows modestly for typical inputs. The tenant
// separator "/" and the escape marker "=" are also escaped here so the
// composed scopeID stays unambiguous (see the spicedb adapter).
// First-colon-splitting "type:id" tuples do NOT use this — they rely on
// first-colon splitting.
func EscapeID(id string) string {
	var b strings.Builder
	start := 0
	for i := 0; i < len(id); i++ {
		c := id[i]
		if escapeSafe(c) {
			continue
		}
		b.WriteString(id[start:i])
		fmt.Fprintf(&b, "=%02X", c)
		start = i + 1
	}
	b.WriteString(id[start:])
	return b.String()
}

// escapeSafe reports whether a byte passes through EscapeID untouched.
// The set is [a-zA-Z0-9_-]: everything SpiceDB allows that never
// collides with the "=" escape marker or the "/" tenant separator.
func escapeSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}

// UnescapeID reverses EscapeID. A bare "=" (not followed by two hex
// digits) is copied through defensively; the encoder never emits one.
func UnescapeID(id string) string {
	if !strings.Contains(id, "=") {
		return id
	}
	var b strings.Builder
	for i := 0; i < len(id); {
		if i+3 <= len(id) && id[i] == '=' {
			if v, ok := hexByte(id[i+1 : i+3]); ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(id[i])
		i++
	}
	return b.String()
}

// hexByte decodes two uppercase/lowercase hex digits into one byte.
func hexByte(s string) (byte, bool) {
	var v byte
	for i := 0; i < 2; i++ {
		c := s[i]
		var n byte
		switch {
		case c >= '0' && c <= '9':
			n = c - '0'
		case c >= 'A' && c <= 'F':
			n = c - 'A' + 10
		case c >= 'a' && c <= 'f':
			n = c - 'a' + 10
		default:
			return 0, false
		}
		v = v<<4 | n
	}
	return v, true
}
