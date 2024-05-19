package cmd

//
//import (
//	"fmt"
//	"github.com/spf13/cobra"
//	"sbom.observer/cli/pkg/buildops"
//)
//
//// repoCmd represents the repo command
//var experimentalCmd = &cobra.Command{
//	Use:    "ex",
//	Short:  "Experimental commands",
//	Long:   `Experimental commands`,
//	Run:    ExperimentalCommands,
//	Hidden: true,
//}
//
//var buildObsCmd = &cobra.Command{
//	Use:   "buildobs",
//	Short: "Experimental build-observations processor",
//	Long:  `Experimental build-observations processor`,
//	Run:   BuildObsCommands,
//	Args:  cobra.ExactArgs(1),
//}
//
//func init() {
//	rootCmd.AddCommand(experimentalCmd)
//	experimentalCmd.AddCommand(buildObsCmd)
//
//	// Here you will define your flags and configuration settings.
//
//	// Cobra supports Persistent Flags which will work for this command
//	// and all subcommands, e.g.:
//	// repoCmd.PersistentFlags().String("foo", "", "A help for foo")
//
//	// Cobra supports local flags which will only run when this command
//	// is called directly, e.g.:
//	// repoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
//}
//
//func ExperimentalCommands(cmd *cobra.Command, args []string) {
//	fmt.Println("experimental commands")
//}
//
//func BuildObsCommands(cmd *cobra.Command, args []string) {
//	observations, err := buildops.ParseFile(args[0])
//	if err != nil {
//		panic(err)
//	}
//
//	dependencyObservations := buildops.DependencyObservations(observations)
//	dependencies, err := buildops.ResolveDependencies(dependencyObservations)
//	if err != nil {
//		panic(err)
//	}
//
//	for _, dep := range dependencies.Code {
//		fmt.Printf("%+v\n", dep)
//	}
//}
