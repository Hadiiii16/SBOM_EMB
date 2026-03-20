package metadata

type EvidenceType string

const (
	EvidenceManifest     EvidenceType = "manifest"
	EvidenceFileName     EvidenceType = "file-name"
	EvidenceDirName      EvidenceType = "dir-name"
	EvidenceBinaryString EvidenceType = "binary-string"
	EvidenceHeaderText   EvidenceType = "header-text"
	EvidenceDocText      EvidenceType = "doc-text"
	EvidenceEnvVar       EvidenceType = "env-var"
	EvidenceELFNeeded    EvidenceType = "elf-needed"
	EvidenceELFSoname    EvidenceType = "elf-soname"
	EvidenceInitScript   EvidenceType = "init-script"
	EvidencePackageDB    EvidenceType = "package-db"
	EvidenceFirmwareBlob EvidenceType = "firmware-blob"
)

type Evidence struct {
	Type       EvidenceType `json:"type" yaml:"type"`
	Location   string       `json:"location" yaml:"location"`
	Key        string       `json:"key,omitempty" yaml:"key,omitempty"`
	Value      string       `json:"value" yaml:"value"`
	Confidence float64      `json:"confidence" yaml:"confidence"`
	RuleID     string       `json:"ruleId,omitempty" yaml:"ruleId,omitempty"`
	Reason     string       `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type CPECandidate struct {
	CPE        string   `json:"cpe" yaml:"cpe"`
	Reason     []string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Confidence float64  `json:"confidence" yaml:"confidence"`
}

type CommercialMetadata struct {
	Vendor             string         `json:"vendor" yaml:"vendor"`
	Product            string         `json:"product" yaml:"product"`
	ProductFamily      string         `json:"productFamily,omitempty" yaml:"productFamily,omitempty"`
	ComponentKind      string         `json:"componentKind,omitempty" yaml:"componentKind,omitempty"`
	Edition            string         `json:"edition,omitempty" yaml:"edition,omitempty"`
	DisplayVersion     string         `json:"displayVersion,omitempty" yaml:"displayVersion,omitempty"`
	NormalizedVersion  string         `json:"normalizedVersion,omitempty" yaml:"normalizedVersion,omitempty"`
	CanonicalID        string         `json:"canonicalId,omitempty" yaml:"canonicalId,omitempty"`
	Aliases            []string       `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Evidence           []Evidence     `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	CPECandidates      []CPECandidate `json:"cpeCandidates,omitempty" yaml:"cpeCandidates,omitempty"`
	SelectedCPE        string         `json:"selectedCpe,omitempty" yaml:"selectedCpe,omitempty"`
	IdentityConfidence float64        `json:"identityConfidence" yaml:"identityConfidence"`
	CPEConfidence      float64        `json:"cpeConfidence" yaml:"cpeConfidence"`
}