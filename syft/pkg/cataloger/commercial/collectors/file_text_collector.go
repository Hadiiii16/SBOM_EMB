package collectors

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial"
)

// path_collector.go에서 사용하는 공용 함수
func normalizePath(p string) string {
	return strings.TrimPrefix(filepath.Clean(p), "/")
}

type FileTextCollector struct {
	keywords []string
}

func NewFileTextCollector(keywords ...string) *FileTextCollector {
	return &FileTextCollector{
		keywords: keywords,
	}
}

// 인터페이스 규격 만족
func (c *FileTextCollector) Name() string {
	return "commercial-file-text-collector"
}

func (c *FileTextCollector) Collect(ctx context.Context, resolver file.Resolver) ([]commercial.CollectedEvidence, error) {
	var results []commercial.CollectedEvidence

	locations, err := resolver.FilesByGlob("**/*")
	if err != nil {
		return nil, err
	}

	for _, location := range locations {
		ext := strings.ToLower(filepath.Ext(location.RealPath))
		if !isTargetExtension(ext) {
			continue
		}

		readCloser, err := resolver.FileContentsByLocation(location)
		if err != nil {
			continue
		}

		// 10MB까지만 읽어서 메모리 보호
		contentBytes, err := io.ReadAll(io.LimitReader(readCloser, 10*1024*1024))
		readCloser.Close()
		if err != nil || len(contentBytes) == 0 {
			continue
		}

		// [핵심] 대소문자 무시를 위해 파일 내용을 전부 소문자로 변환합니다.
		lowerContentBytes := bytes.ToLower(contentBytes)

		for _, kw := range c.keywords {
			// 우리가 찾는 키워드도 소문자로 변환하여 비교합니다.
			lowerKw := bytes.ToLower([]byte(kw))

			if bytes.Contains(lowerContentBytes, lowerKw) {
				
				// 터미널에서 확실하게 볼 수 있도록 로그 출력
				log.Warnf("💥 [BINGO] '%s' 키워드를 찾았습니다: %s", kw, location.RealPath)
				
				results = append(results, commercial.CollectedEvidence{
					Type:     "file_text",
					Location: location.RealPath,
					Value:    kw,
				})
			}
		}
	}
	return results, nil
}

func isTargetExtension(ext string) bool {
	switch ext {
	// 리눅스 커널 모듈(.ko), 공유 라이브러리(.so), 바이너리 실행파일(""), 설정 파일 등
	case ".ko", ".so", ".bin", ".elf", "", ".conf", ".sh", ".json", ".xml", ".txt":
		return true
	}
	return false
}