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

// KRIETool represents the base command of krie-tool
var KRIETool = &cobra.Command{
	Use: "ktool [command] [args]",
}

var Offsets = &cobra.Command{
	Use:   "offsets",
	Short: "Compute a kernel offset from an offset in a System.map file",
	RunE:  offsetsCmd,
}

var Trigger = &cobra.Command{
	Use:   "trigger",
	Short: "Trigger the vuln_device vulnerability",
	RunE:  triggerCmd,
}

var options CLIOptions

func init() {
	KRIETool.Flags().VarP(
		NewKRIEToolOptionsSanitizer(&options, "log_level"),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")

	Offsets.Flags().StringVar(
		&options.SystemMapFile,
		"system-map-file",
		"/boot/System.map-5.4.0-105-generic",
		"System.map file to use when computing offsets")
	Offsets.Flags().StringVar(
		&options.KallsymsSystemMapOffsetSymbol,
		"kallsyms-system-map-offset-symbol",
		"commit_creds",
		"symbol used to compute the diff in offset between /proc/kallsyms and System.map")
	Offsets.Flags().Var(
		NewKRIEToolOptionsSanitizer(&options, "gadget_addr"),
		"gadget",
		"gadget in System.map to translate into /proc/kallsyms")
	Offsets.MarkFlagRequired("gadget")
	Offsets.Flags().BoolVar(
		&options.ComputeOffsetFromFnArray,
		"compute-offset-from-fn-array",
		true,
		"compute the offset between the provided gadget_addr in kernel memory and the fn_array address of vuln_device")

	Trigger.Flags().StringVar(
		&options.VulnDevicePath,
		"vuln-device-path",
		"/dev/vuln_device",
		"path to the vulnerable character device")
	Trigger.Flags().Var(
		NewKRIEToolOptionsSanitizer(&options, "gadget_addr"),
		"gadget",
		"gadget in System.map used to pivot the stack")
	Trigger.MarkFlagRequired("gadget")

	KRIETool.AddCommand(Offsets)
	KRIETool.AddCommand(Trigger)
}
