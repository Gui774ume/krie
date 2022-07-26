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

	"github.com/Gui774ume/krie/pkg/krie"
)

// KRIE represents the base command of krie
var KRIE = &cobra.Command{
	Use:  "krie",
	RunE: krieCmd,
}

var options = CLIOptions{
	KRIEOptions: krie.NewOptions(),
}

func init() {
	KRIE.Flags().Var(
		NewKRIEOptionsSanitizer(&options, "config"),
		"config",
		"KRIE config file, command line arguments erase the content of the config file")
}
