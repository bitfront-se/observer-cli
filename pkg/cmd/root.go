package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/types"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "observer",
	Short: "Create, manage and upload SBOMs to https://sbom.observer",
	Long: `Create, manage and upload SBOMs to https://sbom.observer:

PREVIEW: This is a preview release and is not yet ready for production use.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },

	Version: "dev",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// setup logging
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			log.Logger.SetLevel(log.DebugLevel)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.Version = types.Version
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging (implies silent mode)")
	rootCmd.PersistentFlags().Bool("silent", false, "Silent mode (no progress bars)")
}

func NotImplemented(cmd *cobra.Command, args []string) {
	log.Fatal("Not implemented yet!")
}
