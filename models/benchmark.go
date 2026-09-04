package models

type Benchmark struct {
	ID            string             `yaml:"id"`
	Title         string             `yaml:"title"`
	Description   string             `yaml:"description"`
	Status        string             `yaml:"status"`
	StatusDate    string             `yaml:"status_date"`
	Version       int                `yaml:"version"`
	Release       int                `yaml:"release"`
	BenchmarkDate string             `yaml:"benchmark_date"`
	Reference     BenchmarkReference `yaml:"reference"`
}
