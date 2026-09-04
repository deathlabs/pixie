package convert

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	convertCmd = &cobra.Command{
		Use:   "yaml",
		Short: "Convert YAML to XCCDF",
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
