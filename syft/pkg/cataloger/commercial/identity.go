package commercial

import (
	"fmt"
	"regexp"
	"strings"
)

type ResolvedIdentity struct {
	RuleID              string
	Vendor              string
	Product             string
	ProductFamily       string
	ComponentKind       string
	Aliases             []string
	DisplayVersion      string
	NormalizedVersion   string
	CanonicalID         string
	IdentityConfidence  float64
	CPEConfidence       float64
	MatchedEvidence     []MatchedEvidence
	CPECandidates       []string
	SelectedCPE         string
}

type IdentityResolver struct{}

func NewIdentityResolver() *IdentityResolver {
	return &IdentityResolver{}
}

func (r *IdentityResolver) Resolve(matches []MatchResult) []ResolvedIdentity {
	out := make([]ResolvedIdentity, 0)

	for _, match := range matches {
		if match.Score < match.IdentifyThreshold {
			continue
		}

		displayVersion, normalizedVersion := r.pickVersion(match.VersionCandidates)

		id := ResolvedIdentity{
			RuleID:             match.Rule.ID,
			Vendor:             match.Rule.CanonicalVendor,
			Product:            match.Rule.CanonicalProduct,
			ProductFamily:      match.Rule.ProductFamily,
			ComponentKind:      match.Rule.ComponentKind,
			Aliases:            append([]string{}, match.Rule.Aliases...),
			DisplayVersion:     displayVersion,
			NormalizedVersion:  normalizedVersion,
			CanonicalID:        buildCanonicalID(match.Rule.CanonicalVendor, match.Rule.CanonicalProduct, normalizedVersion),
			IdentityConfidence: match.Score,
			MatchedEvidence:    match.MatchedEvidence,
		}

		id.CPECandidates = expandCPETemplates(match.Rule.CPETemplates, normalizedVersion)
		if match.Score >= match.SelectCPEThreshold && normalizedVersion != "" && len(id.CPECandidates) > 0 {
			id.SelectedCPE = id.CPECandidates[0]
			id.CPEConfidence = match.Score
		}

		out = append(out, id)
	}

	return out
}

func (r *IdentityResolver) pickVersion(candidates []VersionCandidate) (string, string) {
	if len(candidates) == 0 {
		return "", ""
	}

	best := candidates[0].Version
	return best, normalizeVersion(best)
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	v = strings.TrimSpace(v)

	re := regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}`)
	m := re.FindString(v)
	if m == "" {
		return v
	}
	return m
}

func buildCanonicalID(vendor, product, version string) string {
	if version == "" {
		return fmt.Sprintf("%s:%s", vendor, product)
	}
	return fmt.Sprintf("%s:%s:%s", vendor, product, version)
}

func expandCPETemplates(templates []string, version string) []string {
	if len(templates) == 0 {
		return nil
	}

	out := make([]string, 0, len(templates))
	for _, t := range templates {
		if version == "" {
			out = append(out, strings.ReplaceAll(t, "{version}", "*"))
			continue
		}
		out = append(out, strings.ReplaceAll(t, "{version}", version))
	}
	return out
}