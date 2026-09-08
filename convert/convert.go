package convert

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deathlabs/pixie/models/xccdf/cdf"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

type config struct {
	Benchmark    benchmark     `yaml:"benchmark"`
	Requirements []requirement `yaml:"requirements"`
}

type benchmark struct {
	ID            string    `yaml:"id"`
	Title         string    `yaml:"title"`
	Description   string    `yaml:"description"`
	Status        string    `yaml:"status"`
	StatusDate    string    `yaml:"status_date"`
	Version       int       `yaml:"version"`
	Release       int       `yaml:"release"`
	BenchmarkDate string    `yaml:"benchmark_date"`
	Reference     reference `yaml:"reference"`
}

type reference struct {
	Publisher string `yaml:"publisher"`
	Source    string `yaml:"source"`
	Href      string `yaml:"href"`
}

type requirement struct {
	VulnerabilityID   string   `yaml:"vulnerability_id"`
	SourceRequirement string   `yaml:"source_requirement"`
	RequirementID     string   `yaml:"requirement_id"`
	RuleID            string   `yaml:"rule_id"`
	Severity          string   `yaml:"severity"`
	Title             string   `yaml:"title"`
	Discussion        string   `yaml:"discussion"`
	FalsePositives    string   `yaml:"false_positives"`
	FalseNegatives    string   `yaml:"false_negatives"`
	Documentable      bool     `yaml:"documentable"`
	Mitigations       string   `yaml:"mitigations"`
	SeverityOverride  string   `yaml:"severity_override_guidance"`
	PotentialImpacts  string   `yaml:"potential_impacts"`
	ThirdPartyTools   string   `yaml:"third_party_tools"`
	MitigationControl string   `yaml:"mitigation_control"`
	Responsibility    string   `yaml:"responsibility"`
	IAControls        string   `yaml:"ia_controls"`
	CCIs              []string `yaml:"ccis"`
	FixID             string   `yaml:"fix_id"`
	Fix               string   `yaml:"fix"`
	CheckID           string   `yaml:"check_id"`
	Check             string   `yaml:"check"`
}

type benchmarkXML struct {
	XMLName     xml.Name       `xml:"Benchmark"`
	XMLNS       string         `xml:"xmlns,attr"`
	ID          string         `xml:"id,attr"`
	Lang        string         `xml:"http://www.w3.org/XML/1998/namespace lang,attr,omitempty"`
	Status      []statusXML    `xml:"status"`
	Title       []plainTextXML `xml:"title,omitempty"`
	Description []innerTextXML `xml:"description,omitempty"`
	Reference   []referenceXML `xml:"reference,omitempty"`
	Version     versionXML     `xml:"version"`
	Group       []groupXML     `xml:"Group,omitempty"`
}

type statusXML struct {
	Date string `xml:"date,attr,omitempty"`
	Text string `xml:",chardata"`
}

type plainTextXML struct {
	Text string `xml:",chardata"`
}

type innerTextXML struct {
	InnerXML string `xml:",innerxml"`
}

type referenceXML struct {
	Href     string `xml:"href,attr,omitempty"`
	InnerXML string `xml:",innerxml"`
}

type versionXML struct {
	Text string `xml:",chardata"`
}

type groupXML struct {
	ID    string         `xml:"id,attr"`
	Title []innerTextXML `xml:"title,omitempty"`
	Rule  []ruleXML      `xml:"Rule,omitempty"`
}

type ruleXML struct {
	ID        string         `xml:"id,attr"`
	Severity  string         `xml:"severity,attr,omitempty"`
	Weight    string         `xml:"weight,attr,omitempty"`
	Version   *versionXML    `xml:"version,omitempty"`
	Title     []innerTextXML `xml:"title,omitempty"`
	Rationale []innerTextXML `xml:"rationale,omitempty"`
	Ident     []identXML     `xml:"ident,omitempty"`
	FixText   []fixTextXML   `xml:"fixtext,omitempty"`
	Check     []checkXML     `xml:"check,omitempty"`
}

type identXML struct {
	System string `xml:"system,attr"`
	Text   string `xml:",chardata"`
}

type fixTextXML struct {
	FixRef   string `xml:"fixref,attr,omitempty"`
	InnerXML string `xml:",innerxml"`
}

type checkXML struct {
	System       string        `xml:"system,attr"`
	ID           string        `xml:"id,attr,omitempty"`
	CheckContent *innerTextXML `xml:"check-content,omitempty"`
}

const (
	xccdfIDNamespace  = "com.github.deathlabs.pixie"
	xccdfNamespace    = "http://checklists.nist.gov/xccdf/1.2"
	cciSystem         = "http://cyber.mil/cci"
	manualCheckSystem = "https://github.com/deathlabs/pixie/check/manual"
	ruleWeight        = "10.0"
)

var convertCmd = &cobra.Command{
	Use:   "yaml",
	Short: "Convert SRGs and STIGs to XCCDF.",
	RunE:  convert,
}

func convert(cmd *cobra.Command, args []string) error {
	var (
		benchmark                  *cdf.Benchmark
		config                     *config
		data                       []byte
		err                        error
		flags                      *pflag.FlagSet
		inputFilePath              string
		inputFilePathWithoutSuffix string
		outputFilePath             string
	)

	flags = cmd.Flags()

	inputFilePath, err = flags.GetString("input-file")
	if err != nil {
		return err
	}

	outputFilePath, err = flags.GetString("output-file")
	if err != nil {
		return err
	}

	if outputFilePath == "" {
		inputFilePathWithoutSuffix = strings.TrimSuffix(inputFilePath, filepath.Ext(inputFilePath))
		outputFilePath = inputFilePathWithoutSuffix + "-xccdf.xml"
	}

	config, err = loadConfig(inputFilePath)
	if err != nil {
		return err
	}

	benchmark = buildBenchmark(config)

	data, err = marshalXCCDF(benchmark)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFilePath, data, 0644)
}

func marshalXCCDF(benchmark *cdf.Benchmark) ([]byte, error) {
	document := benchmarkXML{
		XMLNS: xccdfNamespace,
		ID:    string(benchmark.Id),
		Lang:  benchmark.XmlLang,
		Version: versionXML{
			Text: benchmark.Version.Text,
		},
	}

	for _, status := range benchmark.Status {
		document.Status = append(
			document.Status,
			statusXML{
				Date: status.Date,
				Text: status.Text,
			},
		)
	}

	for _, title := range benchmark.Title {
		document.Title = append(
			document.Title,
			plainTextXML{
				Text: title.Text,
			},
		)
	}

	for _, description := range benchmark.Description {
		document.Description = append(
			document.Description,
			innerTextXML{
				InnerXML: description.InnerXml,
			},
		)
	}

	for _, reference := range benchmark.Reference {
		document.Reference = append(
			document.Reference,
			referenceXML{
				Href:     reference.Href,
				InnerXML: reference.InnerXml,
			},
		)
	}

	for _, group := range benchmark.Group {
		document.Group = append(
			document.Group,
			marshalGroup(group),
		)
	}

	data, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}

	data = append([]byte(xml.Header), data...)
	data = append(data, '\n')
	return data, nil
}

func marshalGroup(group cdf.GroupType) groupXML {
	result := groupXML{
		ID: group.Id,
	}

	for _, title := range group.Title {
		result.Title = append(
			result.Title,
			innerTextXML{
				InnerXML: title.InnerXml,
			},
		)
	}

	for _, rule := range group.Rule {
		result.Rule = append(
			result.Rule,
			marshalRule(rule),
		)
	}

	return result
}

func marshalRule(rule cdf.RuleType) ruleXML {
	result := ruleXML{
		ID:       rule.Id,
		Severity: rule.Severity,
		Weight:   rule.Weight,
	}

	if rule.Version != nil {
		result.Version = &versionXML{
			Text: rule.Version.Text,
		}
	}

	for _, title := range rule.Title {
		result.Title = append(
			result.Title,
			innerTextXML{
				InnerXML: title.InnerXml,
			},
		)
	}

	for _, rationale := range rule.Rationale {
		result.Rationale = append(
			result.Rationale,
			innerTextXML{
				InnerXML: rationale.InnerXml,
			},
		)
	}

	for _, ident := range rule.Ident {
		result.Ident = append(
			result.Ident,
			identXML{
				System: ident.System,
				Text:   ident.Text,
			},
		)
	}

	for _, fixText := range rule.Fixtext {
		result.FixText = append(
			result.FixText,
			fixTextXML{
				FixRef:   fixText.Fixref,
				InnerXML: fixText.InnerXml,
			},
		)
	}

	for _, check := range rule.Check {
		result.Check = append(
			result.Check,
			marshalCheck(check),
		)
	}

	return result
}

func marshalCheck(check cdf.CheckType) checkXML {
	result := checkXML{
		ID:     check.Id,
		System: check.System,
	}

	if check.CheckContent != nil {
		result.CheckContent = &innerTextXML{
			InnerXML: check.CheckContent.InnerXml,
		}
	}

	return result
}

func loadConfig(path string) (*config, error) {
	var (
		config  config
		decoder *yaml.Decoder
		err     error
		file    *os.File
	)

	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder = yaml.NewDecoder(file)
	decoder.KnownFields(true)

	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func buildBenchmark(config *config) *cdf.Benchmark {
	b := config.Benchmark

	groups := make([]cdf.GroupType, 0, len(config.Requirements))
	for _, requirement := range config.Requirements {
		groups = append(groups, buildGroup(requirement))
	}

	benchmark := &cdf.Benchmark{
		Id:      cdf.BenchmarkIdType(b.ID),
		XmlLang: "en",

		Status: []cdf.Status{
			{
				Date: b.StatusDate,
				Text: b.Status,
			},
		},

		Title: []cdf.TextType{
			{
				XmlLang: "en",
				Text:    strings.TrimSpace(b.Title),
			},
		},

		Description: []cdf.HtmlTextWithSubType{
			{
				XmlLang:  "en",
				InnerXml: xmlText(b.Description),
			},
		},

		Version: cdf.VersionType{
			Text: strconv.Itoa(b.Version),
		},

		Group: groups,
	}

	if b.Reference.Href != "" {
		referenceText := strings.TrimSpace(
			b.Reference.Publisher + " " + b.Reference.Source,
		)

		benchmark.Reference = []cdf.ReferenceType{
			{
				Href:     b.Reference.Href,
				InnerXml: xmlText(referenceText),
			},
		}
	}

	return benchmark
}

func buildGroup(requirement requirement) cdf.GroupType {
	title := requirement.SourceRequirement
	if title == "" {
		title = requirement.RequirementID
	}

	return cdf.GroupType{
		Id: requirement.VulnerabilityID,

		Title: []cdf.TextWithSubType{
			{
				InnerXml: xmlText(title),
			},
		},

		Rule: []cdf.RuleType{
			buildRule(requirement),
		},
	}
}

func buildRule(requirement requirement) cdf.RuleType {
	return cdf.RuleType{
		Id:       requirement.RuleID,
		Severity: requirement.Severity,
		Weight:   ruleWeight,
		Version: &cdf.VersionType{
			Text: ruleVersion(requirement),
		},
		Title: []cdf.TextWithSubType{
			{
				InnerXml: xmlText(requirement.Title),
			},
		},
		Rationale: []cdf.HtmlTextWithSubType{
			{
				InnerXml: xmlText(requirement.Discussion),
			},
		},
		Ident: buildIdents(requirement),
		Fixtext: []cdf.FixTextType{
			buildFixText(requirement),
		},
		Check: []cdf.CheckType{
			buildCheck(requirement),
		},
	}
}

func buildCheck(requirement requirement) cdf.CheckType {
	return cdf.CheckType{
		Id:     requirement.CheckID,
		System: manualCheckSystem,
		CheckContent: &cdf.CheckContentType{
			InnerXml: xmlText(requirement.Check),
		},
	}
}

func buildFixText(requirement requirement) cdf.FixTextType {
	return cdf.FixTextType{
		Fixref:   requirement.FixID,
		InnerXml: xmlText(requirement.Fix),
	}
}

func buildIdents(requirement requirement) []cdf.IdentType {
	idents := make([]cdf.IdentType, 0, len(requirement.CCIs))

	for _, cci := range requirement.CCIs {
		idents = append(
			idents,
			cdf.IdentType{
				System: cciSystem,
				Text:   cci,
			},
		)
	}

	return idents
}

func ruleVersion(requirement requirement) string {
	if requirement.SourceRequirement == "" {
		return requirement.RequirementID
	}

	return requirement.SourceRequirement + "-" + requirement.RequirementID
}

func xmlText(value string) string {
	var out bytes.Buffer

	if err := xml.EscapeText(
		&out,
		[]byte(strings.TrimSpace(value)),
	); err != nil {
		panic(err)
	}

	return out.String()
}
