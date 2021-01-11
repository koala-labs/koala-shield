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

	"github.com/koala-labs/koala-shield/shield"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

// unBlockCmd represents the unBlock command
var unBlockCmd = &cobra.Command{
	Use:   "un-block",
	Short: "Un-block an ASN by removing their IP Set from WAF Rules",
	Run: func(cmd *cobra.Command, args []string) {
		region, err := cmd.Flags().GetString("aws-region")
		if err != nil {
			fmt.Println(aurora.Red(err))
			os.Exit(1)
		}

		s := shield.NewShield(region)

		for _, asn := range args {
			err := s.DisableBlockList(asn)
			if err != nil {
				fmt.Println(aurora.Red(err))
				os.Exit(1)
			}
			fmt.Println(aurora.Sprintf(aurora.Green("Done! %s has been un-blocked!"), asn))
		}
	},
}

func init() {
	rootCmd.AddCommand(unBlockCmd)
}
