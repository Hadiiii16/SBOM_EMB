package collectors

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial"
)

type PathCollector struct{}

func NewPathCollector() *PathCollector {
	return &PathCollector{}
}

func (c *PathCollector) Name() string {
	return "path-collector"
}

func (c *PathCollector) Collect(ctx context.Context, resolver file.Resolver) ([]commercial.CollectedEvidence, error) {
	var out []commercial.CollectedEvidence

	locations, err := resolver.FilesByGlob("**/*")
	if err != nil {
		return nil, err
	}

	for _, loc := range locations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		p := loc.RealPath
		if p == "" {
			p = loc.AccessPath
		}
		p = normalizePath(p)
		if p == "" || p == "." {
			continue
		}

		out = append(out, commercial.CollectedEvidence{
			Type:       commercial.EvidenceTypePath,
			Location:   p,
			Key:        "file",
			Value:      p,
			Collector:  c.Name(),
			Confidence: 0,
		})

		base := filepath.Base(p)
		if base != "" && base != "." && base != "/" {
			out = append(out, commercial.CollectedEvidence{
				Type:       commercial.EvidenceTypePath,
				Location:   p,
				Key:        "basename",
				Value:      base,
				Collector:  c.Name(),
				Confidence: 0,
			})
		}
	}

	return out, nil
}

func normalizePath(p string) string {
	p = filepath.ToSlash(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return filepath.Clean(p)
}

var _ commercial.EvidenceCollector = (*PathCollector)(nil)