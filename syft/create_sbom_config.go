package syft

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/commercial" // 이제 사용됨
	"github.com/anchore/syft/syft/pkg/cataloger/firmware"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOMConfig specifies all parameters needed for creating an SBOM.
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

	// 커스텀 카탈로거 강제 주입
	cfg.WithCatalogers(
		// 1. Firmware 카탈로거
		pkgcataloging.CatalogerReference{
			Cataloger:     firmware.NewCataloger(),
			Tags:          []string{pkgcataloging.PackageTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag},
			AlwaysEnabled: true,
		},
		// 2. Commercial 카탈로거 추가 (import 에러 해결 및 기능 활성화)
		pkgcataloging.CatalogerReference{
			// 주의: commercial.NewCataloger가 인자를 받는 경우 (nil, nil) 등으로 호출하거나 
			// 별도의 기본 생성자를 호출해야 합니다.
			Cataloger:     commercial.NewCataloger(nil), 
			Tags:          []string{pkgcataloging.PackageTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag},
			AlwaysEnabled: true,
		},
	)

	return cfg
}

func syftVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" && d.Version != "(devel)" {
			return d.Version
		}
	}
	return ""
}

func (c *CreateSBOMConfig) WithTool(name, version string, cfg ...any) *CreateSBOMConfig {
	c.ToolName = name
	c.ToolVersion = version
	c.ToolConfiguration = cfg
	return c
}

func (c *CreateSBOMConfig) WithParallelism(p int) *CreateSBOMConfig {
	c.Parallelism = p
	return c
}

func (c *CreateSBOMConfig) WithComplianceConfig(cfg cataloging.ComplianceConfig) *CreateSBOMConfig {
	c.Compliance = cfg
	return c
}

func (c *CreateSBOMConfig) WithSearchConfig(cfg cataloging.SearchConfig) *CreateSBOMConfig {
	c.Search = cfg
	return c
}

func (c *CreateSBOMConfig) WithRelationshipsConfig(cfg cataloging.RelationshipsConfig) *CreateSBOMConfig {
	c.Relationships = cfg
	return c
}

func (c *CreateSBOMConfig) WithUnknownsConfig(cfg cataloging.UnknownsConfig) *CreateSBOMConfig {
	c.Unknowns = cfg
	return c
}

func (c *CreateSBOMConfig) WithDataGenerationConfig(cfg cataloging.DataGenerationConfig) *CreateSBOMConfig {
	c.DataGeneration = cfg
	return c
}

func (c *CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) *CreateSBOMConfig {
	c.Packages = cfg
	return c
}

func (c *CreateSBOMConfig) WithLicenseConfig(cfg cataloging.LicenseConfig) *CreateSBOMConfig {
	c.Licenses = cfg
	return c
}

func (c *CreateSBOMConfig) WithFilesConfig(cfg filecataloging.Config) *CreateSBOMConfig {
	c.Files = cfg
	return c
}

func (c *CreateSBOMConfig) WithoutFiles() *CreateSBOMConfig {
	c.Files = filecataloging.Config{
		Selection: file.NoFilesSelection,
		Hashers:   nil,
	}
	return c
}

func (c *CreateSBOMConfig) WithCatalogerSelection(selection cataloging.SelectionRequest) *CreateSBOMConfig {
	c.CatalogerSelection = selection
	return c
}

func (c *CreateSBOMConfig) WithoutCatalogers() *CreateSBOMConfig {
	c.packageTaskFactories = nil
	c.packageCatalogerReferences = nil
	return c
}

func (c *CreateSBOMConfig) WithCatalogers(catalogerRefs ...pkgcataloging.CatalogerReference) *CreateSBOMConfig {
	for i := range catalogerRefs {
		catalogerRefs[i].Tags = append(catalogerRefs[i].Tags, pkgcataloging.PackageTag)
	}
	c.packageCatalogerReferences = append(c.packageCatalogerReferences, catalogerRefs...)
	return c
}

func (c *CreateSBOMConfig) makeTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
	var taskGroups [][]task.Task

	environmentTasks := c.environmentTasks()
	scopeTasks := c.scopeTasks()
	relationshipsTasks := c.relationshipTasks(src)
	unknownTasks := c.unknownsTasks()
	osFeatureDetectionTasks := c.osFeatureDetectionTasks()

	pkgTasks, fileTasks, selectionEvidence, err := c.selectTasks(src)
	if err != nil {
		return nil, nil, err
	}

	if c.Files.Selection == file.FilesOwnedByPackageSelection {
		taskGroups = append(taskGroups, pkgTasks, fileTasks)
	} else {
		taskGroups = append(taskGroups, append(pkgTasks, fileTasks...))
	}

	if len(scopeTasks) > 0 {
		taskGroups = append(taskGroups, scopeTasks)
	}
	if len(relationshipsTasks) > 0 {
		taskGroups = append(taskGroups, relationshipsTasks)
	}
	if len(unknownTasks) > 0 {
		taskGroups = append(taskGroups, unknownTasks)
	}
	if len(osFeatureDetectionTasks) > 0 {
		taskGroups = append(taskGroups, osFeatureDetectionTasks)
	}

	taskGroups = append([][]task.Task{environmentTasks}, taskGroups...)

	var allTasks []task.Task
	allTasks = append(allTasks, pkgTasks...)
	allTasks = append(allTasks, fileTasks...)

	return taskGroups, &catalogerManifest{
		Requested: selectionEvidence.Request,
		Used:      formatTaskNames(allTasks),
	}, nil
}

func (c *CreateSBOMConfig) fileTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, error) {
	tsks, err := task.DefaultFileTaskFactories().Tasks(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create file cataloger tasks: %w", err)
	}
	return tsks, nil
}

func (c *CreateSBOMConfig) selectTasks(src source.Description) ([]task.Task, []task.Task, *task.Selection, error) {
	cfg := task.CatalogingFactoryConfig{
		SearchConfig:         c.Search,
		RelationshipsConfig:  c.Relationships,
		DataGenerationConfig: c.DataGeneration,
		PackagesConfig:       c.Packages,
		LicenseConfig:        c.Licenses,
		ComplianceConfig:     c.Compliance,
		FilesConfig:          c.Files,
	}

	persistentPkgTasks, selectablePkgTasks, err := c.allPackageTasks(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	req, err := finalTaskSelectionRequest(c.CatalogerSelection, src)
	if err != nil {
		return nil, nil, nil, err
	}

	selectableFileTasks, err := c.fileTasks(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	taskGroups := [][]task.Task{selectablePkgTasks, selectableFileTasks}
	finalTaskGroups, selection, err := task.SelectInGroups(taskGroups, *req)
	if err != nil {
		return nil, nil, nil, err
	}

	if deprecatedNames := deprecatedTasks(finalTaskGroups); len(deprecatedNames) > 0 {
		log.WithFields("catalogers", strings.Join(deprecatedNames, ", ")).Warn("deprecated catalogers are being used")
	}

	finalPkgTasks := finalTaskGroups[0]
	finalFileTasks := finalTaskGroups[1]
	finalPkgTasks = append(finalPkgTasks, persistentPkgTasks...)

	if len(finalPkgTasks) == 0 && len(finalFileTasks) == 0 {
		return nil, nil, nil, fmt.Errorf("no catalogers selected")
	}

	logTaskNames(finalPkgTasks, "package cataloger")
	logTaskNames(finalFileTasks, "file cataloger")

	return finalPkgTasks, finalFileTasks, &selection, nil
}

func deprecatedTasks(taskGroups [][]task.Task) []string {
	_, selection, err := task.SelectInGroups(taskGroups, cataloging.SelectionRequest{DefaultNamesOrTags: []string{pkgcataloging.DeprecatedTag}, RemoveNamesOrTags: []string{filecataloging.FileTag}})
	if err != nil {
		return nil
	}
	return selection.Result.List()
}

func logTaskNames(tasks []task.Task, kind string) {
	log.Debugf("selected %d %s tasks", len(tasks), kind)
	names := formatTaskNames(tasks)
	for idx, t := range names {
		if idx == len(tasks)-1 {
			log.Tracef("└── %s", t)
		} else {
			log.Tracef("├── %s", t)
		}
	}
}

func finalTaskSelectionRequest(req cataloging.SelectionRequest, src source.Description) (*cataloging.SelectionRequest, error) {
	if len(req.DefaultNamesOrTags) == 0 {
		defaultTags, err := findDefaultTags(src)
		if err != nil {
			return nil, fmt.Errorf("unable to determine default cataloger tag: %w", err)
		}
		req.DefaultNamesOrTags = append(req.DefaultNamesOrTags, defaultTags...)
		req.RemoveNamesOrTags = replaceDefaultTagReferences(defaultTags, req.RemoveNamesOrTags)
		req.SubSelectTags = replaceDefaultTagReferences(defaultTags, req.SubSelectTags)
	}
	return &req, nil
}

func (c *CreateSBOMConfig) allPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	persistentPackageTasks, selectablePackageTasks, err := c.userPackageTasks(cfg)
	if err != nil {
		return nil, nil, err
	}
	tsks, err := c.packageTaskFactories.Tasks(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}
	return persistentPackageTasks, append(tsks, selectablePackageTasks...), nil
}

func (c *CreateSBOMConfig) userPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	var (
		persistentPackageTasks []task.Task
		selectablePackageTasks []task.Task
	)
	for _, catalogerRef := range c.packageCatalogerReferences {
		if catalogerRef.Cataloger == nil {
			return nil, nil, errors.New("provided cataloger reference without a cataloger")
		}
		if catalogerRef.AlwaysEnabled {
			persistentPackageTasks = append(persistentPackageTasks, task.NewPackageTask(cfg, catalogerRef.Cataloger, catalogerRef.Tags...))
			continue
		}
		if len(catalogerRef.Tags) == 0 {
			return nil, nil, errors.New("provided cataloger reference without tags")
		}
		selectablePackageTasks = append(selectablePackageTasks, task.NewPackageTask(cfg, catalogerRef.Cataloger, catalogerRef.Tags...))
	}
	return persistentPackageTasks, selectablePackageTasks, nil
}

func (c *CreateSBOMConfig) scopeTasks() []task.Task {
	var tsks []task.Task
	if c.Search.Scope == source.DeepSquashedScope {
		if t := task.NewDeepSquashedScopeCleanupTask(); t != nil {
			tsks = append(tsks, t)
		}
	}
	return tsks
}

func (c *CreateSBOMConfig) relationshipTasks(src source.Description) []task.Task {
	var tsks []task.Task
	if t := task.NewRelationshipsTask(c.Relationships, src); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

func (c *CreateSBOMConfig) environmentTasks() []task.Task {
	var tsks []task.Task
	if t := task.NewEnvironmentTask(); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

func (c *CreateSBOMConfig) unknownsTasks() []task.Task {
	var tasks []task.Task
	if t := task.NewUnknownsLabelerTask(c.Unknowns); t != nil {
		tasks = append(tasks, t)
	}
	return tasks
}

func (c *CreateSBOMConfig) osFeatureDetectionTasks() []task.Task {
	var tasks []task.Task
	if t := task.NewOSFeatureDetectionTask(); t != nil {
		tasks = append(tasks, t)
	}
	return tasks
}

func (c *CreateSBOMConfig) validate() error {
	if c.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		if !c.Relationships.PackageFileOwnershipOverlap {
			return fmt.Errorf("invalid configuration: ownership overlap relationships must be enabled")
		}
	}
	return nil
}

func (c *CreateSBOMConfig) Create(ctx context.Context, src source.Source) (*sbom.SBOM, error) {
	return CreateSBOM(ctx, src, c)
}

func findDefaultTags(src source.Description) ([]string, error) {
	switch m := src.Metadata.(type) {
	case source.ImageMetadata, source.OCIModelMetadata:
		return []string{pkgcataloging.ImageTag, filecataloging.FileTag}, nil
	case source.FileMetadata, source.DirectoryMetadata:
		return []string{pkgcataloging.DirectoryTag, filecataloging.FileTag}, nil
	case source.SnapMetadata:
		return []string{pkgcataloging.InstalledTag, filecataloging.FileTag}, nil
	default:
		return nil, fmt.Errorf("unable to determine default cataloger tag for source type=%T", m)
	}
}

func replaceDefaultTagReferences(defaultTags []string, lst []string) []string {
	for i, tag := range lst {
		if strings.ToLower(tag) == "default" {
			switch len(defaultTags) {
			case 0:
				lst[i] = ""
			case 1:
				lst[i] = defaultTags[0]
			default:
				lst = append(lst[:i], append(defaultTags, lst[i+1:]...)...)
			}
		}
	}
	return lst
}