package syft

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial/collectors"
	"github.com/anchore/syft/syft/pkg/cataloger/firmware"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type CreateSBOMConfig struct {
	Compliance         cataloging.ComplianceConfig
	Search             cataloging.SearchConfig
	Relationships      cataloging.RelationshipsConfig
	Unknowns           cataloging.UnknownsConfig
	DataGeneration     cataloging.DataGenerationConfig
	Packages           pkgcataloging.Config
	Licenses           cataloging.LicenseConfig
	Files              filecataloging.Config
	Parallelism        int
	CatalogerSelection cataloging.SelectionRequest

	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}

	packageTaskFactories      task.Factories
	packageCatalogerReferences []pkgcataloging.CatalogerReference
}

func DefaultCreateSBOMConfig() *CreateSBOMConfig {
	cfg := &CreateSBOMConfig{
		Compliance:           cataloging.DefaultComplianceConfig(),
		Search:               cataloging.DefaultSearchConfig(),
		Relationships:        cataloging.DefaultRelationshipsConfig(),
		DataGeneration:       cataloging.DefaultDataGenerationConfig(),
		Packages:             pkgcataloging.DefaultConfig(),
		Licenses:             cataloging.DefaultLicenseConfig(),
		Files:                filecataloging.DefaultConfig(),
		Parallelism:          0,
		packageTaskFactories: task.DefaultPackageTaskFactories(),
		ToolName:             "syft",
		ToolVersion:          syftVersion(),
	}

	// [🔥 마법의 코드 추가 🔥] 
	// Syft가 중복 파일 소유권을 핑계로 패키지를 무단 삭제하는 것을 원천 차단합니다!
	cfg.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap = false

	// 1. Commercial 규칙 파일 경로 (에러 방지를 위해 절대 경로를 가장 먼저 시도)
	rulePath := "/home/ktdevice/syft/syft/pkg/cataloger/commercial/rules/qualcomm-embedded.yaml"
	ruleSet, err := commercial.LoadRuleSetFromFile(rulePath)

	var commCataloger *commercial.Cataloger
    if err != nil {
        log.Warnf("Commercial rules not loaded from absolute path, trying relative: %v", err)
        // 상대 경로로 재시도
        ruleSet, err = commercial.LoadRuleSetFromFile("syft/pkg/cataloger/commercial/rules/qualcomm-embedded.yaml")
    }

    if err != nil {
        log.Errorf("CRITICAL: Failed to load commercial rules: %v", err)
        commCataloger = commercial.NewCataloger(nil)
    } else {
        log.Infof("Commercial cataloger successfully loaded with %d products", len(ruleSet.Products))
        commCataloger = commercial.NewCataloger(
            ruleSet.Products,
            
            // 👇 바로 이 부분을 아래처럼 바꿉니다! 👇
            collectors.NewFileTextCollector("Qualcomm", "QMI", "modem", "wifi", "ath11k", "ath10k", "cnss", "rmnet", "mhi"),
            
            collectors.NewPathCollector(),
        )
    }

	// 2. 커스텀 카탈로거 주입 (AlwaysEnabled 설정)
	cfg.WithCatalogers(
		pkgcataloging.CatalogerReference{
			Cataloger:     firmware.NewCataloger(),
			Tags:          []string{pkgcataloging.PackageTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag},
			AlwaysEnabled: true,
		},
		pkgcataloging.CatalogerReference{
			Cataloger:     commCataloger,
			Tags:          []string{pkgcataloging.PackageTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag},
			AlwaysEnabled: true,
		},
	)

	return cfg
}

func (c *CreateSBOMConfig) makeTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
	var taskGroups [][]task.Task

	// [복구] 환경 태스크 (File metadata/digests 활성화를 위해 필수)
	envTasks := c.environmentTasks()
	pkgTasks, fileTasks, selection, err := c.selectTasks(src)
	if err != nil {
		return nil, nil, err
	}

	// [그룹 분리] Syft 원본 로직대로 그룹을 나누어야 UI에 모든 정보가 표시됩니다.
	taskGroups = append(taskGroups, envTasks)
	
	if c.Files.Selection == file.FilesOwnedByPackageSelection {
		taskGroups = append(taskGroups, pkgTasks, fileTasks)
	} else {
		// 패키지와 파일을 순차적으로 스캔하도록 그룹핑
		taskGroups = append(taskGroups, pkgTasks)
		taskGroups = append(taskGroups, fileTasks)
	}

	// 추가 후처리 태스크
	if st := c.scopeTasks(); len(st) > 0 { taskGroups = append(taskGroups, st) }
	if rt := c.relationshipTasks(src); len(rt) > 0 { taskGroups = append(taskGroups, rt) }
	if ut := c.unknownsTasks(); len(ut) > 0 { taskGroups = append(taskGroups, ut) }
	if ot := c.osFeatureDetectionTasks(); len(ot) > 0 { taskGroups = append(taskGroups, ot) }

	allTasks := append(pkgTasks, fileTasks...)
	return taskGroups, &catalogerManifest{
		Requested: selection.Request,
		Used:      formatTaskNames(allTasks),
	}, nil
}

func (c *CreateSBOMConfig) selectTasks(src source.Description) ([]task.Task, []task.Task, *task.Selection, error) {
	factoryCfg := task.CatalogingFactoryConfig{
		SearchConfig: c.Search, RelationshipsConfig: c.Relationships, DataGenerationConfig: c.DataGeneration,
		PackagesConfig: c.Packages, LicenseConfig: c.Licenses, ComplianceConfig: c.Compliance, FilesConfig: c.Files,
	}

	persistent, selectable, err := c.allPackageTasks(factoryCfg)
	if err != nil { return nil, nil, nil, err }

	req, err := finalTaskSelectionRequest(c.CatalogerSelection, src)
	if err != nil { return nil, nil, nil, err }

	fileTsks, err := c.fileTasks(factoryCfg)
	if err != nil { return nil, nil, nil, err }

	groups, selection, err := task.SelectInGroups([][]task.Task{selectable, fileTsks}, *req)
	if err != nil { return nil, nil, nil, err }

	// 상용 카탈로거(persistent)를 결과에 포함
	finalPkgTasks := append(groups[0], persistent...)

	return finalPkgTasks, groups[1], &selection, nil
}

func findDefaultTags(src source.Description) ([]string, error) {
	// filecataloging.FileTag가 있어야 File metadata/digests가 활성화됨
	switch src.Metadata.(type) {
	case source.ImageMetadata, source.OCIModelMetadata:
		return []string{pkgcataloging.ImageTag, filecataloging.FileTag}, nil
	case source.FileMetadata, source.DirectoryMetadata:
		return []string{pkgcataloging.DirectoryTag, filecataloging.FileTag}, nil
	case source.SnapMetadata:
		return []string{pkgcataloging.InstalledTag, filecataloging.FileTag}, nil
	default:
		return nil, fmt.Errorf("unable to determine default cataloger tag for source type=%T", src.Metadata)
	}
}

// --- 빌드 유지를 위한 헬퍼 메서드들 ---

func (c *CreateSBOMConfig) allPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	p, s, err := c.userPackageTasks(cfg)
	if err != nil { return nil, nil, err }
	tsks, err := c.packageTaskFactories.Tasks(cfg)
	return p, append(tsks, s...), err
}

func (c *CreateSBOMConfig) userPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	var p, s []task.Task
	for _, ref := range c.packageCatalogerReferences {
		if ref.Cataloger == nil { return nil, nil, errors.New("nil cataloger") }
		tsk := task.NewPackageTask(cfg, ref.Cataloger, ref.Tags...)
		if ref.AlwaysEnabled { p = append(p, tsk) } else { s = append(s, tsk) }
	}
	return p, s, nil
}

func (c *CreateSBOMConfig) fileTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, error) {
	return task.DefaultFileTaskFactories().Tasks(cfg)
}

func finalTaskSelectionRequest(req cataloging.SelectionRequest, src source.Description) (*cataloging.SelectionRequest, error) {
	if len(req.DefaultNamesOrTags) == 0 {
		tags, err := findDefaultTags(src)
		if err != nil { return nil, err }
		req.DefaultNamesOrTags = tags
	}
	return &req, nil
}

func syftVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok { return "" }
	for _, d := range info.Deps {
		if d.Path == "github.com/anchore/syft" && d.Version != "(devel)" { return d.Version }
	}
	return ""
}

func (c *CreateSBOMConfig) Create(ctx context.Context, src source.Source) (*sbom.SBOM, error) { return CreateSBOM(ctx, src, c) }
func (c *CreateSBOMConfig) WithTool(n, v string, cfg ...any) *CreateSBOMConfig { c.ToolName, c.ToolVersion, c.ToolConfiguration = n, v, cfg; return c }
func (c *CreateSBOMConfig) WithParallelism(p int) *CreateSBOMConfig { c.Parallelism = p; return c }
func (c *CreateSBOMConfig) WithSearchConfig(cfg cataloging.SearchConfig) *CreateSBOMConfig { c.Search = cfg; return c }
func (c *CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) *CreateSBOMConfig { c.Packages = cfg; return c }
func (c *CreateSBOMConfig) WithFilesConfig(cfg filecataloging.Config) *CreateSBOMConfig { c.Files = cfg; return c }
func (c *CreateSBOMConfig) WithComplianceConfig(cfg cataloging.ComplianceConfig) *CreateSBOMConfig { c.Compliance = cfg; return c }
func (c *CreateSBOMConfig) WithRelationshipsConfig(cfg cataloging.RelationshipsConfig) *CreateSBOMConfig { c.Relationships = cfg; return c }
func (c *CreateSBOMConfig) WithUnknownsConfig(cfg cataloging.UnknownsConfig) *CreateSBOMConfig { c.Unknowns = cfg; return c }
func (c *CreateSBOMConfig) WithDataGenerationConfig(cfg cataloging.DataGenerationConfig) *CreateSBOMConfig { c.DataGeneration = cfg; return c }
func (c *CreateSBOMConfig) WithLicenseConfig(cfg cataloging.LicenseConfig) *CreateSBOMConfig { c.Licenses = cfg; return c }
func (c *CreateSBOMConfig) WithCatalogerSelection(s cataloging.SelectionRequest) *CreateSBOMConfig { c.CatalogerSelection = s; return c }
func (c *CreateSBOMConfig) WithCatalogers(r ...pkgcataloging.CatalogerReference) *CreateSBOMConfig {
	for i := range r { r[i].Tags = append(r[i].Tags, pkgcataloging.PackageTag) }
	c.packageCatalogerReferences = append(c.packageCatalogerReferences, r...); return c
}
func (c *CreateSBOMConfig) WithoutFiles() *CreateSBOMConfig { c.Files = filecataloging.Config{Selection: file.NoFilesSelection}; return c }
func (c *CreateSBOMConfig) WithoutCatalogers() *CreateSBOMConfig { c.packageTaskFactories, c.packageCatalogerReferences = nil, nil; return c }
func (c *CreateSBOMConfig) scopeTasks() []task.Task { return []task.Task{task.NewDeepSquashedScopeCleanupTask()} }
func (c *CreateSBOMConfig) relationshipTasks(s source.Description) []task.Task { return []task.Task{task.NewRelationshipsTask(c.Relationships, s)} }
func (c *CreateSBOMConfig) environmentTasks() []task.Task { return []task.Task{task.NewEnvironmentTask()} }
func (c *CreateSBOMConfig) unknownsTasks() []task.Task { return []task.Task{task.NewUnknownsLabelerTask(c.Unknowns)} }
func (c *CreateSBOMConfig) osFeatureDetectionTasks() []task.Task { return []task.Task{task.NewOSFeatureDetectionTask()} }
func (c *CreateSBOMConfig) validate() error { return nil }