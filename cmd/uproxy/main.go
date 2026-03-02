package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"

func main() {
	var rootCmd = &cobra.Command{
		Use:   "uproxy",
		Short: "Highly resilient KCP+SSH proxy (client and server)",
		Long: `uproxy is a highly resilient VPN system using KCP+SSH with intelligent 
connectivity monitoring and fast recovery from network issues.`,
		Version: version,
	}

	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(clientCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
