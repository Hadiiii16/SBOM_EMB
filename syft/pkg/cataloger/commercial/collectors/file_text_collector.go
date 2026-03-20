package collectors

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial"
)

const (
	defaultMaxTextFileSize = 2 * 1024 * 1024
	defaultMaxLineLength   = 4096
)

type FileTextCollector struct {
	MaxFileSize int64
}

func NewFileTextCollector() *FileTextCollector {
	return &FileTextCollector{
		MaxFileSize: defaultMaxTextFileSize,
	}
}

func (c *FileTextCollector) Name() string {
	return "file-text-collector"
}

func (c *FileTextCollector) Collect(ctx context.Context, resolver file.Resolver) ([]commercial.CollectedEvidence, error) {
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

		path := loc.RealPath
		if path == "" {
			path = loc.AccessPath
		}
		path = normalizePath(path)

		if !looksLikeTextCandidate(path) {
			continue
		}

		meta, err := resolver.FileMetadataByLocation(loc)
		if err == nil && c.MaxFileSize > 0 && meta.Size > c.MaxFileSize {
			continue
		}

		reader, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			continue
		}

		isText, sample, err := sniffText(reader)
		_ = reader.Close()
		if err != nil || !isText {
			continue
		}

		if sample != "" {
			out = append(out, commercial.CollectedEvidence{
				Type:       commercial.EvidenceTypeText,
				Location:   path,
				Key:        "sample",
				Value:      truncateString(sample, 512),
				Collector:  c.Name(),
				Confidence: 0,
			})
		}

		reader, err = resolver.FileContentsByLocation(loc)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(reader)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, defaultMaxLineLength)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			line = truncateString(line, defaultMaxLineLength)

			out = append(out, commercial.CollectedEvidence{
				Type:       commercial.EvidenceTypeText,
				Location:   path,
				Key:        "line",
				Value:      line,
				Collector:  c.Name(),
				Confidence: 0,
			})
		}

		_ = reader.Close()
	}

	return out, nil
}

func looksLikeTextCandidate(path string) bool {
	lower := strings.ToLower(path)

	textExts := []string{
		".txt", ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
		".sh", ".lua", ".py", ".pl", ".cgi", ".js",
		".html", ".htm", ".md", ".rst",
		".license", ".lic", ".notice",
	}

	for _, ext := range textExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	base := filepath.Base(lower)
	switch base {
	case "readme", "readme.txt", "release_notes", "releasenotes", "license", "notice", "version", "banner":
		return true
	}

	if strings.Contains(lower, "/etc/init.d/") ||
		strings.Contains(lower, "/etc/config/") ||
		strings.Contains(lower, "/usr/share/") ||
		strings.Contains(lower, "/etc/") {
		return true
	}

	return false
}

func sniffText(r io.Reader) (bool, string, error) {
	const sniffSize = 4096

	buf := make([]byte, sniffSize)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return false, "", err
	}
	buf = buf[:n]
	if len(buf) == 0 {
		return false, "", nil
	}
	if bytes.IndexByte(buf, 0x00) >= 0 {
		return false, "", nil
	}
	return true, strings.TrimSpace(string(buf)), nil
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

var _ commercial.EvidenceCollector = (*FileTextCollector)(nil)