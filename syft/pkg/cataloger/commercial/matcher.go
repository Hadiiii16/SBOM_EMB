package commercial

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type MatchResult struct {
	Rule               ProductRule
	Score              float64
	IdentifyThreshold  float64
	SelectCPEThreshold float64
	MatchedEvidence    []MatchedEvidence
	VersionCandidates  []VersionCandidate
}

type VersionCandidate struct {
	Version    string
	Confidence float64
	Source     string
	Location   string
}

type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) Match(evidence []CollectedEvidence, rules []ProductRule) []MatchResult {
	results := make([]MatchResult, 0, len(rules))

	for _, rule := range rules {
		result := MatchResult{
			Rule:               rule,
			IdentifyThreshold:  defaultThreshold(rule.Thresholds.Identify, 0.80),
			SelectCPEThreshold: defaultThreshold(rule.Thresholds.SelectCPE, 0.95),
		}

		// path markers
		for _, marker := range rule.PathMarkers {
			for _, ev := range evidence {
				if ev.Type != EvidenceTypePath {
					continue
				}
				if globMatch(marker.Glob, ev.Location) || globMatch(marker.Glob, ev.Value) {
					result.Score += marker.Confidence
					result.MatchedEvidence = append(result.MatchedEvidence, MatchedEvidence{
						Type:       ev.Type,
						Location:   ev.Location,
						Key:        ev.Key,
						Value:      ev.Value,
						Collector:  ev.Collector,
						Confidence: marker.Confidence,
						Reason:     "matched path marker: " + marker.Glob,
					})
				}
			}
		}

		// text markers
		for _, marker := range rule.TextMarkers {
			for _, ev := range evidence {
				if ev.Type != EvidenceTypeText {
					continue
				}
				if !globMatch(marker.FileGlob, ev.Location) {
					continue
				}

				matched := false
				if marker.Contains != "" && strings.Contains(strings.ToLower(ev.Value), strings.ToLower(marker.Contains)) {
					matched = true
				}
				if marker.Regex != "" {
					if ok, _ := regexMatch(marker.Regex, ev.Value); ok {
						matched = true
					}
				}
				if !matched {
					continue
				}

				result.Score += marker.Confidence
				result.MatchedEvidence = append(result.MatchedEvidence, MatchedEvidence{
					Type:       ev.Type,
					Location:   ev.Location,
					Key:        ev.Key,
					Value:      ev.Value,
					Collector:  ev.Collector,
					Confidence: marker.Confidence,
					Reason:     "matched text marker",
				})
			}
		}

		// negative matchers
		for _, neg := range rule.NegativeMatchers {
			for _, ev := range evidence {
				if !globMatch(neg.FileGlob, ev.Location) {
					continue
				}

				matched := false
				if neg.Contains != "" && strings.Contains(strings.ToLower(ev.Value), strings.ToLower(neg.Contains)) {
					matched = true
				}
				if neg.Regex != "" {
					if ok, _ := regexMatch(neg.Regex, ev.Value); ok {
						matched = true
					}
				}
				if !matched {
					continue
				}

				result.Score -= neg.ConfidencePenalty
				result.MatchedEvidence = append(result.MatchedEvidence, MatchedEvidence{
					Type:       ev.Type,
					Location:   ev.Location,
					Key:        ev.Key,
					Value:      ev.Value,
					Collector:  ev.Collector,
					Confidence: -neg.ConfidencePenalty,
					Reason:     "matched negative marker",
				})
			}
		}

		// version hints
		for _, hint := range rule.VersionHints {
			for _, ev := range evidence {
				switch hint.Source {
				case "file_text":
					if ev.Type != EvidenceTypeText {
						continue
					}
					if hint.FileGlob != "" && !globMatch(hint.FileGlob, ev.Location) {
						continue
					}
					if version, ok := regexCaptureFirst(hint.Regex, ev.Value); ok {
						result.VersionCandidates = append(result.VersionCandidates, VersionCandidate{
							Version:    version,
							Confidence: hint.Confidence,
							Source:     hint.Source,
							Location:   ev.Location,
						})
					}
				case "path":
					if ev.Type != EvidenceTypePath {
						continue
					}
					if hint.FileGlob != "" && !globMatch(hint.FileGlob, ev.Location) {
						continue
					}
					if version, ok := regexCaptureFirst(hint.Regex, ev.Location); ok {
						result.VersionCandidates = append(result.VersionCandidates, VersionCandidate{
							Version:    version,
							Confidence: hint.Confidence,
							Source:     hint.Source,
							Location:   ev.Location,
						})
					}
				}
			}
		}

		sort.SliceStable(result.VersionCandidates, func(i, j int) bool {
			return result.VersionCandidates[i].Confidence > result.VersionCandidates[j].Confidence
		})

		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

func defaultThreshold(v, fallback float64) float64 {
	if v == 0 {
		return fallback
	}
	return v
}

func globMatch(pattern, target string) bool {
	if pattern == "" {
		return false
	}

	target = filepath.ToSlash(target)
	pattern = filepath.ToSlash(pattern)

	ok, err := filepath.Match(pattern, target)
	if err == nil && ok {
		return true
	}

	// filepath.Match 는 ** 를 제대로 처리하지 않으므로 보완
	if strings.Contains(pattern, "**") {
		pattern = strings.ReplaceAll(pattern, "**", "*")
		ok, err = filepath.Match(pattern, target)
		if err == nil && ok {
			return true
		}
	}

	// fallback: contains 형태로 약하게 처리
	needle := strings.ReplaceAll(pattern, "*", "")
	needle = strings.ReplaceAll(needle, "?", "")
	needle = strings.TrimSpace(needle)
	if needle != "" && strings.Contains(target, needle) {
		return true
	}

	return false
}

func regexMatch(expr, value string) (bool, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return false, err
	}
	return re.MatchString(value), nil
}

func regexCaptureFirst(expr, value string) (string, bool) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return "", false
	}
	m := re.FindStringSubmatch(value)
	if len(m) < 2 {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}