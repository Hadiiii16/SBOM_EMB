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
	var evidence []metadata2.Evidence
	var locs []file.Location

	// 1. MatchedEvidence에서 실제 발견된 파일 경로(Location)들을 추출합니다.
	for _, me := range identity.MatchedEvidence {
		ev := metadata2.Evidence{
			Confidence: identity.IdentityConfidence,
		}
		evidence = append(evidence, ev)
		
		// [핵심 수정] 패키지가 삭제되지 않도록 실제 발견된 파일 경로를 추가합니다.
		if me.Location != "" {
			locs = append(locs, file.NewLocation(me.Location))
		}
	}

	// 만약 증거에서 경로를 하나도 못 가져왔다면, Syft 삭제 방지를 위해 가상의 경로를 넣습니다.
	if len(locs) == 0 {
		locs = append(locs, file.NewLocation("commercial-rule-match"))
	}

	// 2. CPE 변환
	var cpeCandidates []metadata2.CPECandidate
	for _, c := range identity.CPECandidates {
		cpeCandidates = append(cpeCandidates, metadata2.CPECandidate{
			CPE:        c,
			Confidence: identity.CPEConfidence,
		})
	}

	// 3. 메타데이터 구성
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

	// [핵심 수정] 버전이 텅 비어있으면 삭제될 수 있으므로 "unknown"으로 방어합니다.
	finalVersion := m.DisplayVersion
	if finalVersion == "" {
		finalVersion = "unknown"
	}

	// 4. 최종 패키지 반환
	return pkg.Package{
		Name:      m.Product,
		Version:   finalVersion,
		Locations: file.NewLocationSet(locs...), 
		
		// [핵심 수정] pkg.BinaryPkg 대신 커스텀 타입을 지정하여 Syft의 중복 제거를 회피합니다.
		Type:      pkg.Type("commercial-stack"), 
		
		Language:  pkg.Language(m.ComponentKind),
		Metadata:  m,
	}
}

// NewPackage 함수 쪽도 동일하게 수정해 줍니다.
func (b *PackageBuilder) NewPackage(m metadata2.CommercialMetadata, locations ...file.Location) pkg.Package {
	finalVersion := m.DisplayVersion
	if finalVersion == "" {
		finalVersion = "unknown"
	}
	
	return pkg.Package{
		Name:      m.Product,
		Version:   finalVersion,
		Locations: file.NewLocationSet(locations...),
		
		// [핵심 수정] 여기도 변경
		Type:      pkg.Type("commercial-stack"),
		
		Language:  pkg.Language(m.ComponentKind),
		Metadata:  m,
	}
}