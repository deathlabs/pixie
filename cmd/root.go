package cmd

import (
	"fmt"
	"os"

	"github.com/deathlabs/pixie/convert"
	"github.com/spf13/cobra"
)

var (
	inputFilePath  string
	outputFilePath string
	version        string // Default version, overridden by build flags.
	rootCmd        = &cobra.Command{
		Use:     "pixie",
		Short:   "Pixie is a CLI tool for converting YAML to XCCDF",
		Version: version,
	}
)

func Execute() {
	var err = rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputFilePath, "input-file", "i", "", "Input file")
	rootCmd.PersistentFlags().StringVarP(&outputFilePath, "output-file", "o", "", "Output file")
	rootCmd.AddCommand(convert.Cmd)
}
