package models

type BenchmarkReference struct {
	Publisher string `yaml:"publisher"`
	Source    string `yaml:"source"`
	Href      string `yaml:"href"`
}
