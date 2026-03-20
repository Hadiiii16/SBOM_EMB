package commercial

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadRuleSetFromFile(path string) (RuleSet, error) {
	var rs RuleSet

	b, err := os.ReadFile(path)
	if err != nil {
		return rs, err
	}

	if err := yaml.Unmarshal(b, &rs); err != nil {
		return rs, fmt.Errorf("yaml unmarshal failed: %w", err)
	}

	if err := ValidateRuleSet(rs); err != nil {
		return rs, err
	}

	return rs, nil
}

func ValidateRuleSet(rs RuleSet) error {
	if strings.TrimSpace(rs.Vendor) == "" {
		return fmt.Errorf("ruleset vendor is required")
	}
	if len(rs.Products) == 0 {
		return fmt.Errorf("ruleset %q has no products", rs.Vendor)
	}

	seen := map[string]struct{}{}
	for _, p := range rs.Products {
		if strings.TrimSpace(p.ID) == "" {
			return fmt.Errorf("product rule id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate product rule id: %s", p.ID)
		}
		seen[p.ID] = struct{}{}

		if strings.TrimSpace(p.CanonicalVendor) == "" {
			return fmt.Errorf("product %q canonical_vendor is required", p.ID)
		}
		if strings.TrimSpace(p.CanonicalProduct) == "" {
			return fmt.Errorf("product %q canonical_product is required", p.ID)
		}

		if p.Thresholds.Identify <= 0 || p.Thresholds.Identify > 1.0 {
			return fmt.Errorf("product %q thresholds.identify must be > 0 and <= 1", p.ID)
		}
		if p.Thresholds.SelectCPE < 0 || p.Thresholds.SelectCPE > 1.0 {
			return fmt.Errorf("product %q thresholds.select_cpe must be >= 0 and <= 1", p.ID)
		}

		if len(p.PathMarkers)+len(p.TextMarkers)+len(p.ELFMarkers)+len(p.InitMarkers)+len(p.PackageDBMarkers) == 0 {
			return fmt.Errorf("product %q has no markers defined", p.ID)
		}
	}

	return nil
}