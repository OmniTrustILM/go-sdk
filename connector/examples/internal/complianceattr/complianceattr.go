// Package complianceattr is the kind attribute schema shared by the
// compliance-v1 and compliance-v2 examples (compliance.KindAttributeProvider):
// one required string attribute naming the compliance profile to evaluate
// against. The two compliance model packages generate distinct Go types, so
// each example's store keeps only the thin model-typed glue (building the
// DataAttributeV3, reading request attribute names); the schema values and the
// validation rule live here once.
package complianceattr

const (
	ProfileUUID        = "44444444-4444-4444-4444-444444444444"
	ProfileName        = "profile"
	ProfileLabel       = "Profile"
	ProfileDescription = "Compliance profile to evaluate against"

	// MsgMissingProfile is the semantic validation error for a request
	// without the profile attribute (rendered as a v1 422 []string).
	MsgMissingProfile = "missing required attribute profile"
)

// Validate requires the profile attribute among attrs, identified by the name
// that name extracts (empty for attributes the caller does not recognise, e.g.
// non-V3 request attributes). Placeholder: the content is not inspected.
// Returns nil when valid, otherwise the validation messages.
func Validate[A any](attrs []A, name func(A) string) []string {
	for _, a := range attrs {
		if name(a) == ProfileName {
			return nil
		}
	}
	return []string{MsgMissingProfile}
}
