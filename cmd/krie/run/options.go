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
	"fmt"
	"os"

	"github.com/Gui774ume/krie/pkg/krie"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	Config      string
	KRIEOptions *krie.Options
}

// KRIEOptionsSanitizer is a generic options sanitizer for KRIE
type KRIEOptionsSanitizer struct {
	field   string
	options *CLIOptions
}

// NewKRIEOptionsSanitizer creates a new instance of KRIEOptionsSanitizer
func NewKRIEOptionsSanitizer(options *CLIOptions, field string) *KRIEOptionsSanitizer {
	options.Config = "./cmd/krie/run/config/default_config.yaml"

	return &KRIEOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (kos *KRIEOptionsSanitizer) String() string {
	switch kos.field {
	case "config":
		return kos.options.Config
	default:
		return ""
	}
}

func (kos *KRIEOptionsSanitizer) Set(val string) error {
	switch kos.field {
	case "config":
		_, err := os.Stat(val)
		if err != nil {
			return fmt.Errorf("couldn't find config file %s: %w", val, err)
		}
		return nil
	default:
		return nil
	}
}

func (kos *KRIEOptionsSanitizer) Type() string {
	switch kos.field {
	case "config":
		return "string"
	default:
		return ""
	}
}
