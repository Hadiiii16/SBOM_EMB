package firmware

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

//go:embed qualcomm_golden_db.json
var qualcommGoldenDBData []byte

type GoldenEntry struct {
	Chipset            string `json:"chipset"`
	OfficialCPEProduct string `json:"official_cpe_product"`
	SourceFile         string `json:"source_file"`
	Signatures         struct {
		Critical []string `json:"critical"`
		Optional []string `json:"optional"`
	} `json:"signatures"`
}

type Cataloger struct {
	db []GoldenEntry
}

func NewCataloger() *Cataloger {
	var db []GoldenEntry
	if err := json.Unmarshal(qualcommGoldenDBData, &db); err != nil {
		return nil
	}
	return &Cataloger{db: db}
}

func (c *Cataloger) Name() string {
	return "qualcomm-embedded-cataloger"
}

// 바이너리에서 문자열 추출 로직
func (c *Cataloger) extractStrings(r io.Reader, minLength int) string {
	data, err := io.ReadAll(r)
	if err != nil {
		return ""
	}

	var result []string
	var current []rune
	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) && !unicode.IsSpace(r) {
			current = append(current, r)
		} else {
			if len(current) >= minLength {
				result = append(result, string(current))
			}
			current = nil
		}
	}
	return strings.Join(result, " ")
}

func (c *Cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	// 대상 파일 탐색
	fmt.Printf("🔍 [DEBUG] Qualcomm 분석 시작: %d개 DB 항목 로드됨\n", len(c.db))
	locations, err := resolver.FilesByGlob("**/*.{bin,ko,so}")
	if err != nil {
		return nil, nil, err
	}

	for _, location := range locations {
		// [해결] Open 대신 FileContentsByLocation 사용
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			continue
		}
		
		contentBlob := c.extractStrings(contentReader, 10)
		_ = contentReader.Close()
		
		for _, entry := range c.db {
			matchCount := 0
			detectedVersion := "unknown"

			for _, sig := range entry.Signatures.Critical {
				if strings.Contains(contentBlob, sig) {
					matchCount++
					if strings.Contains(sig, ".") && len(sig) > 8 {
						detectedVersion = sig
					}
				}
			}

			// [해결] RealPath는 함수가 아닌 필드이므로 직접 접근
			if matchCount >= 2 || (matchCount >= 1 && strings.Contains(location.RealPath, entry.SourceFile)) {
				
				// 패키지 생성 (v1.x 구조 준수)
				p := pkg.Package{
					Name:      entry.OfficialCPEProduct,
					Version:   detectedVersion,
					// [해결] NewLocationSet을 사용하여 LocationSet 타입 생성
					Locations: file.NewLocationSet(location),
					Type:      pkg.BinaryPkg,
					Language:  "C",
					CPEs: []cpe.CPE{
						// [해결] cpe.Must에 cpe.GeneratedSource 인자 추가
						cpe.Must(fmt.Sprintf("cpe:2.3:o:qualcomm:%s:%s:*:*:*:*:*:*:*", entry.OfficialCPEProduct, detectedVersion), cpe.GeneratedSource),
					},
				}
				
				// [해결] Metadata 할당
				p.Metadata = map[string]interface{}{
					"chipset":    entry.Chipset,
					"matchLevel": "high-precision-embedded",
					"foundBy":    c.Name(),
				}

				packages = append(packages, p)
				break
			}
		}
	}
	return packages, nil, nil
}