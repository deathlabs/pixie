package models

type Config struct {
	Benchmark    Benchmark     `yaml:"benchmark"`
	Requirements []Requirement `yaml:"requirements"`
}
