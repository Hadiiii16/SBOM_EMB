package commercial

type RuleSet struct {
	Vendor   string        `yaml:"vendor"`
	Products []ProductRule `yaml:"products"`
}

type ProductRule struct {
	ID               string            `yaml:"id"`
	CanonicalVendor  string            `yaml:"canonical_vendor"`
	CanonicalProduct string            `yaml:"canonical_product"`
	ProductFamily    string            `yaml:"product_family,omitempty"`
	ComponentKind    string            `yaml:"component_kind,omitempty"`
	Aliases          []string          `yaml:"aliases,omitempty"`
	PathMarkers      []PathMarker      `yaml:"path_markers,omitempty"`
	TextMarkers      []TextMarker      `yaml:"text_markers,omitempty"`
	ELFMarkers       []ELFMarker       `yaml:"elf_markers,omitempty"`
	InitMarkers      []InitMarker      `yaml:"init_markers,omitempty"`
	PackageDBMarkers []PackageDBMarker `yaml:"package_db_markers,omitempty"`
	VersionHints     []VersionHint     `yaml:"version_hints,omitempty"`
	CPETemplates     []string          `yaml:"cpe_templates,omitempty"`
	Thresholds       RuleThresholds    `yaml:"thresholds,omitempty"`
	NegativeMatchers []NegativeMatcher `yaml:"negative_matchers,omitempty"`
}

type RuleThresholds struct {
	Identify  float64 `yaml:"identify"`
	SelectCPE float64 `yaml:"select_cpe"`
}

type PathMarker struct {
	Glob       string  `yaml:"glob"`
	Confidence float64 `yaml:"confidence"`
}

type TextMarker struct {
	FileGlob   string  `yaml:"file_glob"`
	Contains   string  `yaml:"contains,omitempty"`
	Regex      string  `yaml:"regex,omitempty"`
	Confidence float64 `yaml:"confidence"`
}

type ELFMarker struct {
	FileGlob     string  `yaml:"file_glob"`
	NeededRegex  string  `yaml:"needed_regex,omitempty"`
	SonameRegex  string  `yaml:"soname_regex,omitempty"`
	StringsRegex string  `yaml:"strings_regex,omitempty"`
	Confidence   float64 `yaml:"confidence"`
}

type InitMarker struct {
	ScriptGlob     string  `yaml:"script_glob"`
	ContainsRegex  string  `yaml:"contains_regex,omitempty"`
	CommandRegex   string  `yaml:"command_regex,omitempty"`
	Confidence     float64 `yaml:"confidence"`
}

type PackageDBMarker struct {
	DBGlob      string  `yaml:"db_glob"`
	PackageName string  `yaml:"package_name,omitempty"`
	Contains    string  `yaml:"contains,omitempty"`
	Confidence  float64 `yaml:"confidence"`
}

type VersionHint struct {
	Source     string  `yaml:"source"` // file_text | path | elf_strings | package_db
	FileGlob   string  `yaml:"file_glob,omitempty"`
	Regex      string  `yaml:"regex"`
	Confidence float64 `yaml:"confidence"`
}

type NegativeMatcher struct {
	FileGlob           string  `yaml:"file_glob"`
	Contains           string  `yaml:"contains,omitempty"`
	Regex              string  `yaml:"regex,omitempty"`
	ConfidencePenalty  float64 `yaml:"confidence_penalty"`
}