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

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/koala-labs/koala-shield/shield"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

// lookupCmd represents the lookup command
var lookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Lookup information about IP addresses and ASN numbers",
	Run: func(cmd *cobra.Command, args []string) {
		region, err := cmd.Flags().GetString("aws-region")
		if err != nil {
			fmt.Println(aurora.Red(err))
			os.Exit(1)
		}
		s := shield.NewShield(region)

		output := []table.Row{}

		for _, record := range args {
			lookup, err := s.Lookup(record)
			if err != nil {
				fmt.Println(aurora.Red(err))
				os.Exit(1)
			}
			output = append(output, table.Row{
				lookup.Type,
				lookup.Record,
				lookup.AsnName,
				lookup.AsnNumber,
				lookup.AsnDescription,
				lookup.AsnIPv4Count,
				countryCodeToEmoji(lookup.AsnCountry),
			})
		}

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Type", "Record", "ASN Name", "ASN Number", "ASN Description", "ASN IPv4 Prefixes", "ASN Country"})
		t.AppendRows(output)
		t.Render()
	},
}

func countryCodeToEmoji(code string) string {
	return string(0x1F1E6+rune(code[0])-'A') + string(0x1F1E6+rune(code[1])-'A')
}

func init() {
	rootCmd.AddCommand(lookupCmd)
}
