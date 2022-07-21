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
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	LogLevel logrus.Level

	// offsets command
	SystemMapFile                 string
	KallsymsSystemMapOffsetSymbol string
	SystemMapGadgetAddr           uint64
	ComputeOffsetFromFnArray      bool

	// trigger command
	VulnDevicePath string
}

// KRIEToolOptionsSanitizer is a generic options sanitizer for KRIE
type KRIEToolOptionsSanitizer struct {
	field   string
	options *CLIOptions
}

// NewKRIEToolOptionsSanitizer creates a new instance of KRIEOptionsSanitizer
func NewKRIEToolOptionsSanitizer(options *CLIOptions, field string) *KRIEToolOptionsSanitizer {
	// set default values here
	options.LogLevel = logrus.InfoLevel

	return &KRIEToolOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (os *KRIEToolOptionsSanitizer) String() string {
	switch os.field {
	case "log_level":
		return fmt.Sprintf("%v", os.options.LogLevel)
	case "gadget_addr":
		return fmt.Sprintf("0x%x", os.options.SystemMapGadgetAddr)
	default:
		return ""
	}
}

func (os *KRIEToolOptionsSanitizer) Set(val string) error {
	switch os.field {
	case "log_level":
		sanitized, err := logrus.ParseLevel(val)
		if err != nil {
			return err
		}
		os.options.LogLevel = sanitized
		return nil
	case "gadget_addr":
		sanitized, err := strconv.ParseUint(strings.TrimPrefix(val, "0x"), 16, 64)
		if err != nil {
			return fmt.Errorf("couldn't parse integer from %s: %v", val, err)
		}
		os.options.SystemMapGadgetAddr = sanitized
		return nil
	default:
		return nil
	}
}

func (uos *KRIEToolOptionsSanitizer) Type() string {
	switch uos.field {
	case "log_level":
		return "string"
	case "gadget_addr":
		return "hex"
	default:
		return ""
	}
}
