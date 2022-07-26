/*
Copyright © 2022 GUILLAUME FOURNIER

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

package run

import (
	"github.com/spf13/cobra"
)

// KRIE represents the base command of krie
var KRIE = &cobra.Command{
	Use:  "krie",
	RunE: krieCmd,
}

var options CLIOptions

func init() {
	KRIE.Flags().VarP(
		NewKRIEOptionsSanitizer(&options.KRIEOptions, "log_level"),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")

	KRIE.Flags().VarP(
		NewKRIEOptionsSanitizer(&options.KRIEOptions, "output"),
		"output",
		"o",
		"JSON output file")

	KRIE.Flags().Var(
		NewKRIEOptionsSanitizer(&options.KRIEOptions, "vmlinux"),
		"vmlinux",
		"BTF information for the current kernel in .tar.xz format (required only if KRIE isn't able to locate it by itself)")

	KRIE.Flags().Var(
		NewKRIEOptionsSanitizer(&options.KRIEOptions, "event"),
		"event",
		"List of events to activate (empty means everything)")
}
