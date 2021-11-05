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
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

var blockCmd = &cobra.Command{
	Use:   "block",
	Short: "Block all the prefixes owned by an ASN using an AWS WAF IP list",
	Run: func(cmd *cobra.Command, args []string) {
		s := shield.NewShield()

		for _, asn := range args {
			err := s.CreateBlockList(asn)
			if err != nil {
				fmt.Println(aurora.Red(err))
				os.Exit(1)
			}

			prompt := promptui.Prompt{
				Label:     fmt.Sprintf("Block IP Set for ASN %s", asn),
				IsConfirm: true,
			}

			_, err = prompt.Run()

			if err != nil {
				fmt.Println(aurora.Red("Canceling block. IP Set exists but is not enabled."))
				os.Exit(1)
			}

			fmt.Println(aurora.Blue("Enabling block in AWS WAF..."))

			err = s.EnableBlockList(asn)
			if err != nil {
				fmt.Println(aurora.Red(err))
				os.Exit(1)
			}

			fmt.Println(aurora.Sprintf(aurora.Green("Done! ASN %s has been blocked!"), asn))
		}
	},
}

func init() {
	rootCmd.AddCommand(blockCmd)
}
