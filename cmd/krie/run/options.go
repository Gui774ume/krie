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

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/krie/pkg/krie"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	KRIEOptions krie.Options
}

// KRIEOptionsSanitizer is a generic options sanitizer for KRIE
type KRIEOptionsSanitizer struct {
	field   string
	options *krie.Options
}

// NewKRIEOptionsSanitizer creates a new instance of KRIEOptionsSanitizer
func NewKRIEOptionsSanitizer(options *krie.Options, field string) *KRIEOptionsSanitizer {
	// set default values here
	options.LogLevel = logrus.InfoLevel

	return &KRIEOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (os *KRIEOptionsSanitizer) String() string {
	switch os.field {
	case "log_level":
		return fmt.Sprintf("%v", os.options.LogLevel)
	default:
		return ""
	}
}

func (os *KRIEOptionsSanitizer) Set(val string) error {
	switch os.field {
	case "log_level":
		sanitized, err := logrus.ParseLevel(val)
		if err != nil {
			return err
		}
		os.options.LogLevel = sanitized
		return nil
	default:
		return nil
	}
}

func (uos *KRIEOptionsSanitizer) Type() string {
	switch uos.field {
	case "log_level":
		return "string"
	default:
		return ""
	}
}
