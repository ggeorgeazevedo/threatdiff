package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// SARIF 2.1.0 output. This is what makes findings appear as inline annotations
// in the GitHub "Files changed" view via code scanning, which is the difference
// between a report someone opens and a note that appears exactly where the
// reviewer is already looking.

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolURI      = "https://github.com/ggeorgeazevedo/threatdiff"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	Results           []sarifResult     `json:"results"`
	Invocations       []sarifInvocation `json:"invocations,omitempty"`
	AutomationDetails *sarifAutomation  `json:"automationDetails,omitempty"`
	ColumnKind        string            `json:"columnKind,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     sarifText        `json:"shortDescription"`
	FullDescription      *sarifText       `json:"fullDescription,omitempty"`
	Help                 *sarifMultiText  `json:"help,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifMultiText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppress   `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int        `json:"startLine"`
	Snippet   *sarifText `json:"snippet,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

// SARIF writes a SARIF 2.1.0 log.
func SARIF(w io.Writer, r *Report) error {
	all := append(append([]*analyze.Finding{}, r.Result.Findings...), r.Result.Suppressed...)

	index := map[string]int{}
	var ruleDefs []sarifRule
	var results []sarifResult

	for _, f := range all {
		idx, ok := index[f.RuleID]
		if !ok {
			idx = len(ruleDefs)
			index[f.RuleID] = idx
			ruleDefs = append(ruleDefs, sarifRuleFor(f))
		}

		res := sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           idx,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{Text: sarifMessage(f)},
			PartialFingerprints: map[string]string{"threatdiff/v1": f.Fingerprint},
			Properties: map[string]any{
				"category":   string(f.Category),
				"confidence": string(f.Confidence),
				"trigger":    string(f.Trigger),
				"score":      f.Score,
			},
		}
		if len(f.Reviewers) > 0 {
			res.Properties["reviewers"] = f.Reviewers
		}
		if f.File != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
			}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
				if f.Snippet != "" {
					loc.PhysicalLocation.Region.Snippet = &sarifText{Text: f.Snippet}
				}
			}
			res.Locations = append(res.Locations, loc)
		}
		if f.Suppressed {
			kind := "inSource"
			if f.SuppressBy == "baseline" {
				kind = "external"
			}
			res.Suppressions = []sarifSuppress{{Kind: kind, Justification: f.Reason}}
		}
		results = append(results, res)
	}

	if ruleDefs == nil {
		ruleDefs = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "threatdiff",
				Version:        r.Meta.Version,
				InformationURI: toolURI,
				Rules:          ruleDefs,
			}},
			Results:           results,
			Invocations:       []sarifInvocation{{ExecutionSuccessful: true}},
			AutomationDetails: &sarifAutomation{ID: "threatdiff/pull-request"},
			ColumnKind:        "utf16CodeUnits",
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("writing sarif: %w", err)
	}
	return nil
}

func sarifRuleFor(f *analyze.Finding) sarifRule {
	help := strings.TrimSpace(f.Question)
	if f.Guidance != "" {
		help += "\n\n" + f.Guidance
	}
	props := map[string]any{
		// GitHub uses security-severity to decide which alerts block a merge.
		"security-severity": securitySeverity(f.Severity),
		"precision":         precision(f.Confidence),
		"tags":              sarifTags(f),
	}
	rule := sarifRule{
		ID:                   f.RuleID,
		Name:                 f.RuleID,
		ShortDescription:     sarifText{Text: f.Title},
		FullDescription:      &sarifText{Text: firstLine(f.Question)},
		Help:                 &sarifMultiText{Text: help, Markdown: help},
		DefaultConfiguration: &sarifRuleConfig{Level: sarifLevel(f.Severity)},
		Properties:           props,
	}
	if len(f.Refs) > 0 {
		rule.HelpURI = f.Refs[0]
	}
	return rule
}

func sarifTags(f *analyze.Finding) []string {
	tags := []string{"security", string(f.Category)}
	tags = append(tags, f.CWE...)
	for _, o := range f.OWASP {
		tags = append(tags, strings.Fields(o)[0])
	}
	tags = append(tags, f.Tags...)
	return tags
}

func sarifMessage(f *analyze.Finding) string {
	msg := f.Title + ". " + firstLine(f.Question)
	if f.Section != "" {
		msg += " (in " + f.Section + ")"
	}
	return msg
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps onto the 0-10 scale GitHub reads. The values line up
// with the CVSS bands it uses for its own severity labels.
func securitySeverity(s rules.Severity) string {
	switch s {
	case rules.Critical:
		return "9.3"
	case rules.High:
		return "7.5"
	case rules.Medium:
		return "5.3"
	case rules.Low:
		return "3.1"
	default:
		return "1.0"
	}
}

func precision(c rules.Confidence) string {
	switch c {
	case rules.ConfHigh:
		return "high"
	case rules.ConfMedium:
		return "medium"
	default:
		return "low"
	}
}
