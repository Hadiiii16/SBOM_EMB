package collectors

import (
	"context"
	"path/filepath"

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

		// normalizePath는 같은 패키지의 file_text_collector.go에 정의된 것을 공유합니다.
		p = normalizePath(p)
		if p == "" || p == "." {
			continue
		}

		// 1. 전체 경로 증거 추가
		out = append(out, commercial.CollectedEvidence{
			Type:       commercial.EvidenceTypePath,
			Location:   p,
			Key:        "file",
			Value:      p,
			Collector:  c.Name(),
			Confidence: 0,
		})

		// 2. 파일명(basename) 증거 추가
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

var _ commercial.EvidenceCollector = (*PathCollector)(nil)