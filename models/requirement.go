package models

type Requirement struct {
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
