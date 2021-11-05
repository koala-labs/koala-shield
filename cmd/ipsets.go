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

var ipsetsCmd = &cobra.Command{
	Use:   "ipsets",
	Short: "List all IP sets registered in AWS WAF",
	Run: func(cmd *cobra.Command, args []string) {

		s := shield.NewShield()

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"WAF Type", "IP Set Name", "IP Set ID", "IP Set Count"})

		sets, err := s.ListIPSets()
		if err != nil {
			fmt.Println(aurora.Red(err))
			os.Exit(1)
		}
		rows := []table.Row{}
		for _, set := range sets {
			rows = append(rows, table.Row{"WAF Classic", set.Name, set.ID, len(set.IPs)})
		}

		t.AppendRows(rows)
		t.Render()
	},
}

func init() {
	rootCmd.AddCommand(ipsetsCmd)
}
