/*
Package cmd .

Copyright © 2021 Walter Beller-Morales engineering@koala.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "koala-shield",
	Short: "A command line tool to quickly research, identify, and block malicious IPs",
	Long: `Koala Shield is a command line tool for tracing an IP address 
to it's Autonomous System Number (ASN) and then quickly blocking all 
requests originating from a malicious actor by using AWS WAF.
	
Examples:

	koala-shield lookup 8.6.8.0 --> find information about the IP address

	koala-shield block 20473 --> block the ASN 20473 using AWS WAF

Be careful when blocking an entire ASN! Make sure the ASN owner is never 
a commercial or residential ISP!`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
}

// initConfig reads in ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		// ENV variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores.
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			viper.BindEnv(f.Name, fmt.Sprintf("%s", envVarSuffix))
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			rootCmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}
