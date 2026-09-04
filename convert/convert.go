package convert

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deathlabs/pixie/models"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

var (
	convertCmd = &cobra.Command{
		Use:   "yaml",
		Short: "Convert SRGs and STIGs to YAML or XCCDF.",
		RunE:  convert,
	}
)

func convert(cmd *cobra.Command, args []string) error {
	var (
		inputFilePath  string
		err            error
		flags          *pflag.FlagSet
		outputFilePath string
	)

	// Read the flags previously given to the provided the command.
	flags = cmd.Flags()

	// Get the input file path from the flag set.
	inputFilePath, err = flags.GetString("input-file")
	if err != nil {
		return err
	}

	// Get the output file path from the flag set.
	outputFilePath, err = flags.GetString("output-file")
	if err != nil {
		return err
	}

	fmt.Println("Input file path:", inputFilePath)
	fmt.Println("Output file path:", outputFilePath)

	return nil
}

const (
	conventionsVersion = "1.10.0"
	ruleWeight         = "10.0"
)

var profiles = []models.Profile{
	{
		ID:    "MAC-1_Classified",
		Title: "I - Mission Critical Classified",
	},
	{
		ID:    "MAC-1_Public",
		Title: "I - Mission Critical Public",
	},
	{
		ID:    "MAC-1_Sensitive",
		Title: "I - Mission Critical Sensitive",
	},
	{
		ID:    "MAC-2_Classified",
		Title: "II - Mission Support Classified",
	},
	{
		ID:    "MAC-2_Public",
		Title: "II - Mission Support Public",
	},
	{
		ID:    "MAC-2_Sensitive",
		Title: "II - Mission Support Sensitive",
	},
	{
		ID:    "MAC-3_Classified",
		Title: "III - Administrative Classified",
	},
	{
		ID:    "MAC-3_Public",
		Title: "III - Administrative Public",
	},
	{
		ID:    "MAC-3_Sensitive",
		Title: "III - Administrative Sensitive",
	},
}

var (
	vulnerabilityPattern = regexp.MustCompile(`^V-[0-9]+$`)
	rulePattern          = regexp.MustCompile(`^SV-[A-Za-z0-9._-]+_rule$`)
	fixPattern           = regexp.MustCompile(`^F-[A-Za-z0-9._-]+_fix$`)
	checkPattern         = regexp.MustCompile(`^C-[A-Za-z0-9._-]+_chk$`)
	cciPattern           = regexp.MustCompile(`^CCI-[0-9]{6}$`)
	requirementPattern   = regexp.MustCompile(`^[A-Z0-9]+-[0-9]{6}$`)
	sourcePattern        = regexp.MustCompile(`^SRG-[A-Z0-9]+-[0-9]{6}$`)
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(
			os.Stderr,
			"usage: %s <input.yaml> <output.xml>\n",
			filepath.Base(os.Args[0]),
		)
		os.Exit(2)
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	config, err := loadConfig(inputPath)
	if err != nil {
		fatal(err)
	}

	if err := validateConfig(config); err != nil {
		fatal(err)
	}

	xccdf, err := buildXCCDF(config, filepath.Base(outputPath))
	if err != nil {
		fatal(err)
	}

	if err := os.WriteFile(outputPath, xccdf, 0644); err != nil {
		fatal(fmt.Errorf("write %s: %w", outputPath, err))
	}

	fmt.Printf(
		"Generated %s with %d requirements\n",
		outputPath,
		len(config.Requirements),
	)
}

func loadConfig(path string) (*models.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var config models.Config

	decoder := yaml.NewDecoder(file)

	// Fail if the YAML contains fields that do not exist
	// in the Go schema. This catches authoring typos.
	decoder.KnownFields(true)

	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	return &config, nil
}

func validateConfig(config *models.Config) error {
	if config == nil {
		return errors.New("configuration is nil")
	}

	b := config.Benchmark

	if strings.TrimSpace(b.ID) == "" {
		return errors.New("benchmark.id is required")
	}

	if strings.TrimSpace(b.Title) == "" {
		return errors.New("benchmark.title is required")
	}

	if strings.TrimSpace(b.Description) == "" {
		return errors.New("benchmark.description is required")
	}

	switch b.Status {
	case "accepted", "deprecated", "draft", "incomplete", "interim":
	default:
		return fmt.Errorf(
			"benchmark.status %q is invalid",
			b.Status,
		)
	}

	if _, err := time.Parse("2006-01-02", b.StatusDate); err != nil {
		return fmt.Errorf(
			"benchmark.status_date must use YYYY-MM-DD: %w",
			err,
		)
	}

	if _, err := time.Parse("2006-01-02", b.BenchmarkDate); err != nil {
		return fmt.Errorf(
			"benchmark.benchmark_date must use YYYY-MM-DD: %w",
			err,
		)
	}

	if b.Version < 1 {
		return errors.New("benchmark.version must be at least 1")
	}

	if b.Release < 1 {
		return errors.New("benchmark.release must be at least 1")
	}

	if strings.TrimSpace(b.Reference.Publisher) == "" {
		return errors.New("benchmark.reference.publisher is required")
	}

	if strings.TrimSpace(b.Reference.Source) == "" {
		return errors.New("benchmark.reference.source is required")
	}

	if strings.TrimSpace(b.Reference.Href) == "" {
		return errors.New("benchmark.reference.href is required")
	}

	if len(config.Requirements) == 0 {
		return errors.New("at least one requirement is required")
	}

	vulnerabilityIDs := map[string]struct{}{}
	ruleIDs := map[string]struct{}{}
	fixIDs := map[string]struct{}{}
	checkIDs := map[string]struct{}{}
	versions := map[string]struct{}{}

	for i, requirement := range config.Requirements {
		n := i + 1

		if !vulnerabilityPattern.MatchString(requirement.VulnerabilityID) {
			return fmt.Errorf(
				"requirement %d: invalid vulnerability_id %q",
				n,
				requirement.VulnerabilityID,
			)
		}

		if _, exists := vulnerabilityIDs[requirement.VulnerabilityID]; exists {
			return fmt.Errorf(
				"requirement %d: duplicate vulnerability_id %q",
				n,
				requirement.VulnerabilityID,
			)
		}
		vulnerabilityIDs[requirement.VulnerabilityID] = struct{}{}

		if requirement.SourceRequirement != "" &&
			!sourcePattern.MatchString(requirement.SourceRequirement) {
			return fmt.Errorf(
				"requirement %d: invalid source_requirement %q",
				n,
				requirement.SourceRequirement,
			)
		}

		if !requirementPattern.MatchString(requirement.RequirementID) {
			return fmt.Errorf(
				"requirement %d: invalid requirement_id %q",
				n,
				requirement.RequirementID,
			)
		}

		if !rulePattern.MatchString(requirement.RuleID) {
			return fmt.Errorf(
				"requirement %d: invalid rule_id %q",
				n,
				requirement.RuleID,
			)
		}

		if _, exists := ruleIDs[requirement.RuleID]; exists {
			return fmt.Errorf(
				"requirement %d: duplicate rule_id %q",
				n,
				requirement.RuleID,
			)
		}
		ruleIDs[requirement.RuleID] = struct{}{}

		if !fixPattern.MatchString(requirement.FixID) {
			return fmt.Errorf(
				"requirement %d: invalid fix_id %q",
				n,
				requirement.FixID,
			)
		}

		if _, exists := fixIDs[requirement.FixID]; exists {
			return fmt.Errorf(
				"requirement %d: duplicate fix_id %q",
				n,
				requirement.FixID,
			)
		}
		fixIDs[requirement.FixID] = struct{}{}

		if !checkPattern.MatchString(requirement.CheckID) {
			return fmt.Errorf(
				"requirement %d: invalid check_id %q",
				n,
				requirement.CheckID,
			)
		}

		if _, exists := checkIDs[requirement.CheckID]; exists {
			return fmt.Errorf(
				"requirement %d: duplicate check_id %q",
				n,
				requirement.CheckID,
			)
		}
		checkIDs[requirement.CheckID] = struct{}{}

		switch requirement.Severity {
		case "low", "medium", "high":
		default:
			return fmt.Errorf(
				"requirement %d: invalid severity %q",
				n,
				requirement.Severity,
			)
		}

		if strings.TrimSpace(requirement.Title) == "" {
			return fmt.Errorf(
				"requirement %d: title is required",
				n,
			)
		}

		if strings.TrimSpace(requirement.Discussion) == "" {
			return fmt.Errorf(
				"requirement %d: discussion is required",
				n,
			)
		}

		if strings.TrimSpace(requirement.Fix) == "" {
			return fmt.Errorf(
				"requirement %d: fix is required",
				n,
			)
		}

		if strings.TrimSpace(requirement.Check) == "" {
			return fmt.Errorf(
				"requirement %d: check is required",
				n,
			)
		}

		if len(requirement.CCIs) == 0 {
			return fmt.Errorf(
				"requirement %d: at least one CCI is required",
				n,
			)
		}

		for _, cci := range requirement.CCIs {
			if !cciPattern.MatchString(cci) {
				return fmt.Errorf(
					"requirement %d: invalid CCI %q",
					n,
					cci,
				)
			}
		}

		version := ruleVersion(requirement)

		if _, exists := versions[version]; exists {
			return fmt.Errorf(
				"requirement %d: duplicate generated version %q",
				n,
				version,
			)
		}
		versions[version] = struct{}{}
	}

	return nil
}

func buildXCCDF(config *models.Config, outputFilename string) ([]byte, error) {
	var out bytes.Buffer

	b := config.Benchmark

	benchmarkDate, err := formatDISADate(b.BenchmarkDate)
	if err != nil {
		return nil, err
	}

	out.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	out.WriteByte('\n')

	out.WriteString(
		`<?xml-stylesheet type='text/xsl' href='STIG_unclass.xsl'?>`,
	)
	out.WriteByte('\n')

	fmt.Fprintf(
		&out,
		`<Benchmark xmlns:dc="http://purl.org/dc/elements/1.1/" `+
			`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" `+
			`xmlns:cpe="http://cpe.mitre.org/language/2.0" `+
			`xmlns:xhtml="http://www.w3.org/1999/xhtml" `+
			`xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" `+
			`xsi:schemaLocation="http://checklists.nist.gov/xccdf/1.1 `+
			`http://nvd.nist.gov/schema/xccdf-1.1.4.xsd `+
			`http://cpe.mitre.org/dictionary/2.0 `+
			`http://cpe.mitre.org/files/cpe-dictionary_2.1.xsd" `+
			`id="%s" xml:lang="en" `+
			`xmlns="http://checklists.nist.gov/xccdf/1.1">`,
		escape(b.ID),
	)
	out.WriteByte('\n')

	fmt.Fprintf(
		&out,
		`  <status date="%s">%s</status>`+"\n",
		escape(b.StatusDate),
		escape(b.Status),
	)

	fmt.Fprintf(
		&out,
		"  <title>%s</title>\n",
		escape(b.Title),
	)

	fmt.Fprintf(
		&out,
		"  <description>%s</description>\n",
		escape(strings.TrimSpace(b.Description)),
	)

	out.WriteString(
		`  <notice id="terms-of-use" xml:lang="en"></notice>` + "\n",
	)
	out.WriteString(
		`  <front-matter xml:lang="en"></front-matter>` + "\n",
	)
	out.WriteString(
		`  <rear-matter xml:lang="en"></rear-matter>` + "\n",
	)

	fmt.Fprintf(
		&out,
		`  <reference href="%s">`+"\n",
		escape(b.Reference.Href),
	)

	fmt.Fprintf(
		&out,
		"    <dc:publisher>%s</dc:publisher>\n",
		escape(b.Reference.Publisher),
	)

	fmt.Fprintf(
		&out,
		"    <dc:source>%s</dc:source>\n",
		escape(b.Reference.Source),
	)

	out.WriteString("  </reference>\n")

	fmt.Fprintf(
		&out,
		`  <plain-text id="release-info">Release: %d Benchmark Date: %s</plain-text>`+"\n",
		b.Release,
		escape(benchmarkDate),
	)

	fmt.Fprintf(
		&out,
		`  <plain-text id="generator">%s</plain-text>`+"\n",
		escape("pixie"),
	)

	fmt.Fprintf(
		&out,
		`  <plain-text id="conventionsVersion">%s</plain-text>`+"\n",
		escape(conventionsVersion),
	)

	fmt.Fprintf(
		&out,
		"  <version>%d</version>\n",
		b.Version,
	)

	writeProfiles(&out, config.Requirements)

	for _, requirement := range config.Requirements {
		writeRequirement(
			&out,
			requirement,
			outputFilename,
		)
	}

	out.WriteString("</Benchmark>\n")

	return out.Bytes(), nil
}

func writeProfiles(out *bytes.Buffer, requirements []models.Requirement) {
	for _, profile := range profiles {
		fmt.Fprintf(
			out,
			`  <Profile id="%s">`+"\n",
			escape(profile.ID),
		)

		fmt.Fprintf(
			out,
			"    <title>%s</title>\n",
			escape(profile.Title),
		)

		out.WriteString(
			"    <description>" +
				escape("<ProfileDescription></ProfileDescription>") +
				"</description>\n",
		)

		for _, requirement := range requirements {
			fmt.Fprintf(
				out,
				`    <select idref="%s" selected="true"/>`+"\n",
				escape(requirement.VulnerabilityID),
			)
		}

		out.WriteString("  </Profile>\n")
	}
}

func writeRequirement(
	out *bytes.Buffer,
	requirement models.Requirement,
	outputFilename string,
) {
	fmt.Fprintf(
		out,
		`  <Group id="%s">`+"\n",
		escape(requirement.VulnerabilityID),
	)

	groupTitle := requirement.SourceRequirement
	if groupTitle == "" {
		groupTitle = requirement.RequirementID
	}

	fmt.Fprintf(
		out,
		"    <title>%s</title>\n",
		escape(groupTitle),
	)

	out.WriteString(
		"    <description>" +
			escape("<GroupDescription></GroupDescription>") +
			"</description>\n",
	)

	fmt.Fprintf(
		out,
		`    <Rule id="%s" weight="%s" severity="%s">`+"\n",
		escape(requirement.RuleID),
		ruleWeight,
		escape(requirement.Severity),
	)

	fmt.Fprintf(
		out,
		"      <version>%s</version>\n",
		escape(ruleVersion(requirement)),
	)

	fmt.Fprintf(
		out,
		"      <title>%s</title>\n",
		escape(strings.TrimSpace(requirement.Title)),
	)

	description := buildRuleDescription(requirement)

	fmt.Fprintf(
		out,
		"      <description>%s</description>\n",
		escape(description),
	)

	for _, cci := range requirement.CCIs {
		fmt.Fprintf(
			out,
			`      <ident system="http://cyber.mil/cci">%s</ident>`+"\n",
			escape(cci),
		)
	}

	fmt.Fprintf(
		out,
		`      <fixtext fixref="%s">%s</fixtext>`+"\n",
		escape(requirement.FixID),
		escape(strings.TrimSpace(requirement.Fix)),
	)

	fmt.Fprintf(
		out,
		`      <fix id="%s"/>`+"\n",
		escape(requirement.FixID),
	)

	fmt.Fprintf(
		out,
		`      <check system="%s">`+"\n",
		escape(requirement.CheckID),
	)

	fmt.Fprintf(
		out,
		`        <check-content-ref href="%s" name="M"/>`+"\n",
		escape(outputFilename),
	)

	fmt.Fprintf(
		out,
		"        <check-content>%s</check-content>\n",
		escape(strings.TrimSpace(requirement.Check)),
	)

	out.WriteString("      </check>\n")
	out.WriteString("    </Rule>\n")
	out.WriteString("  </Group>\n")
}

func buildRuleDescription(requirement models.Requirement) string {
	var description strings.Builder

	// These are XML elements stored as text inside the
	// XCCDF <description> element, matching DISA's format.
	writeEmbeddedField(
		&description,
		"VulnDiscussion",
		requirement.Discussion,
	)

	writeEmbeddedField(
		&description,
		"FalsePositives",
		requirement.FalsePositives,
	)

	writeEmbeddedField(
		&description,
		"FalseNegatives",
		requirement.FalseNegatives,
	)

	fmt.Fprintf(
		&description,
		"<Documentable>%t</Documentable>",
		requirement.Documentable,
	)

	writeEmbeddedField(
		&description,
		"Mitigations",
		requirement.Mitigations,
	)

	writeEmbeddedField(
		&description,
		"SeverityOverrideGuidance",
		requirement.SeverityOverride,
	)

	writeEmbeddedField(
		&description,
		"PotentialImpacts",
		requirement.PotentialImpacts,
	)

	writeEmbeddedField(
		&description,
		"ThirdPartyTools",
		requirement.ThirdPartyTools,
	)

	writeEmbeddedField(
		&description,
		"MitigationControl",
		requirement.MitigationControl,
	)

	writeEmbeddedField(
		&description,
		"Responsibility",
		requirement.Responsibility,
	)

	writeEmbeddedField(
		&description,
		"IAControls",
		requirement.IAControls,
	)

	return description.String()
}

func writeEmbeddedField(
	builder *strings.Builder,
	name string,
	value string,
) {
	fmt.Fprintf(
		builder,
		"<%s>%s</%s>",
		name,
		escape(strings.TrimSpace(value)),
		name,
	)
}

func ruleVersion(requirement models.Requirement) string {
	if requirement.SourceRequirement == "" {
		return requirement.RequirementID
	}

	return requirement.SourceRequirement +
		"-" +
		requirement.RequirementID
}

func formatDISADate(value string) (string, error) {
	date, err := time.Parse("2006-01-02", value)
	if err != nil {
		return "", fmt.Errorf(
			"parse benchmark date %q: %w",
			value,
			err,
		)
	}

	return date.Format("02 Jan 2006"), nil
}

func escape(value string) string {
	var out bytes.Buffer

	if err := xml.EscapeText(&out, []byte(value)); err != nil {
		// bytes.Buffer never returns a write error.
		panic(err)
	}

	return out.String()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
