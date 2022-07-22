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
	"path/filepath"

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

func (kos *KRIEOptionsSanitizer) String() string {
	switch kos.field {
	case "log_level":
		return fmt.Sprintf("%v", kos.options.LogLevel)
	case "output":
		return kos.options.Output
	case "vmlinux":
		return kos.options.VMLinux
	default:
		return ""
	}
}

func (kos *KRIEOptionsSanitizer) Set(val string) error {
	switch kos.field {
	case "log_level":
		sanitized, err := logrus.ParseLevel(val)
		if err != nil {
			return err
		}
		kos.options.LogLevel = sanitized
		return nil
	case "output":
		// create output directory
		_ = os.MkdirAll(filepath.Dir(val), 0644)
		kos.options.Output = val
		return nil
	case "vmlinux":
		// check if the provided file exists
		_, err := os.Stat(val)
		if err != nil {
			return fmt.Errorf("couldn't find vmlinux: %w", err)
		}
		kos.options.VMLinux = val
		return nil
	default:
		return nil
	}
}

func (kos *KRIEOptionsSanitizer) Type() string {
	switch kos.field {
	case "log_level":
		return "string"
	case "output":
		return "string"
	case "vmlinux":
		return "string"
	default:
		return ""
	}
}
