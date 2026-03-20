package commercial

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	metadata2 "github.com/anchore/syft/syft/pkg/pkg/metadata"
)

// PackageBuilder는 식별된 결과(ResolvedIdentity)를 Syft의 Package 객체로 변환합니다.
type PackageBuilder struct {
}

// NewPackageBuilder는 PackageBuilder의 새 인스턴스를 생성합니다.
func NewPackageBuilder() *PackageBuilder {
	return &PackageBuilder{}
}

// Build는 cataloger.go에서 호출되며, ResolvedIdentity의 필드들을 CommercialMetadata에 매핑합니다.
func (b *PackageBuilder) Build(identity ResolvedIdentity) pkg.Package {
	// 1. MatchedEvidence를 metadata2.Evidence 구조체 슬라이스로 변환
	var evidence []metadata2.Evidence
	
	// identity.MatchedEvidence의 개수만큼 루프를 돌며 슬라이스를 생성합니다.
	// 변수 'me'를 사용하지 않으므로 'range'만 사용하여 선언 미사용 에러를 방지합니다.
	for range identity.MatchedEvidence {
		ev := metadata2.Evidence{
			// 현재 identity.go에는 개별 증거의 상세 위치 정보가 포함되어 있지 않으므로
			// 패키지 전체의 신뢰도를 할당합니다.
			Confidence: identity.IdentityConfidence,
		}
		evidence = append(evidence, ev)
	}

	// 2. []string 형태의 CPECandidates를 []metadata2.CPECandidate 구조체로 변환
	var cpeCandidates []metadata2.CPECandidate
	for _, c := range identity.CPECandidates {
		cpeCandidates = append(cpeCandidates, metadata2.CPECandidate{
			CPE:        c,
			Confidence: identity.CPEConfidence,
		})
	}

	// 3. CommercialMetadata 구성 (identity.go에 정의된 필드명과 100% 일치시킴)
	m := metadata2.CommercialMetadata{
		Vendor:             identity.Vendor,
		Product:            identity.Product,
		ProductFamily:      identity.ProductFamily,
		ComponentKind:      identity.ComponentKind,
		DisplayVersion:     identity.DisplayVersion,
		NormalizedVersion:  identity.NormalizedVersion,
		CanonicalID:        identity.CanonicalID,
		Aliases:            identity.Aliases,
		Evidence:           evidence,
		CPECandidates:      cpeCandidates,
		SelectedCPE:        identity.SelectedCPE,
		IdentityConfidence: identity.IdentityConfidence,
		CPEConfidence:      identity.CPEConfidence,
	}

	// 4. 최종 Syft 패키지 객체 생성 및 반환
	return pkg.Package{
		Name:      m.Product,
		Version:   m.DisplayVersion,
		// identity 구조체에 Locations 필드가 없으므로 빈 세트로 초기화합니다.
		Locations: file.NewLocationSet(), 
		Type:      pkg.BinaryPkg,
		Language:  pkg.Language(m.ComponentKind),
		Metadata:  m,
	}
}

// NewPackage는 수동으로 메타데이터를 조합하여 패키지를 생성할 때 사용합니다.
func (b *PackageBuilder) NewPackage(m metadata2.CommercialMetadata, locations ...file.Location) pkg.Package {
	return pkg.Package{
		Name:      m.Product,
		Version:   m.DisplayVersion,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.BinaryPkg,
		Language:  pkg.Language(m.ComponentKind),
		Metadata:  m,
	}
}