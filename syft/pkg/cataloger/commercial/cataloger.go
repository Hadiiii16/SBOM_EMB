package commercial

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type Cataloger struct {
	collectors []EvidenceCollector
	matcher    *Matcher
	resolver   *IdentityResolver
	builder    *PackageBuilder
	rules      []ProductRule
}

func NewCataloger(rules []ProductRule, collectors ...EvidenceCollector) *Cataloger {
	return &Cataloger{
		collectors: collectors,
		matcher:    NewMatcher(),
		resolver:   NewIdentityResolver(),
		builder:    NewPackageBuilder(),
		rules:      rules,
	}
}

func NewCatalogerFromRuleSet(rs *RuleSet, collectors ...EvidenceCollector) *Cataloger {
	return NewCataloger(rs.Products, collectors...)
}

func (c *Cataloger) Name() string {
	return "commercial-embedded-cataloger"
}

func (c *Cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var allEvidence []CollectedEvidence

	for _, collector := range c.collectors {
		ev, err := collector.Collect(ctx, resolver)
		if err != nil {
			return nil, nil, err
		}
		allEvidence = append(allEvidence, ev...)
	}

	matches := c.matcher.Match(allEvidence, c.rules)
	identities := c.resolver.Resolve(matches)

	packages := make([]pkg.Package, 0, len(identities))
	for _, identity := range identities {
		packages = append(packages, c.builder.Build(identity))
	}

	return packages, nil, nil
}