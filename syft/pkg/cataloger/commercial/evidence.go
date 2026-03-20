package commercial

import (
	"context"

	"github.com/anchore/syft/syft/file"
)

type EvidenceType string

const (
	EvidenceTypePath       EvidenceType = "path"
	EvidenceTypeText       EvidenceType = "text"
	EvidenceTypeELFSONAME  EvidenceType = "elf-soname"
	EvidenceTypeELFNeeded  EvidenceType = "elf-needed"
	EvidenceTypeELFString  EvidenceType = "elf-string"
	EvidenceTypeInitScript EvidenceType = "init-script"
	EvidenceTypePackageDB  EvidenceType = "package-db"
	EvidenceTypeFirmware   EvidenceType = "firmware"
)

type CollectedEvidence struct {
	Type        EvidenceType
	Location    string
	Key         string
	Value       string
	Collector   string
	Confidence  float64
	MatchedRule string
}

type MatchedEvidence struct {
	Type       EvidenceType
	Location   string
	Key        string
	Value      string
	Collector  string
	Confidence float64
	Reason     string
}

type EvidenceCollector interface {
	Name() string
	Collect(ctx context.Context, resolver file.Resolver) ([]CollectedEvidence, error)
}