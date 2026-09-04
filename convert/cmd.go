package convert

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use: "convert",
}

func init() {
	Cmd.AddCommand(convertCmd)
}
