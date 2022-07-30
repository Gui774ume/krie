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
	"os/signal"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Gui774ume/krie/pkg/krie"
)

func parseConfig() error {
	f, err := os.Open(options.Config)
	if err != nil {
		return fmt.Errorf("couldn't load config file %s: %w", options.Config, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	if err = decoder.Decode(&options.KRIEOptions); err != nil {
		return fmt.Errorf("couldn't decode config file %s: %w", options.Config, err)
	}

	// create output directory
	if len(options.KRIEOptions.Output) > 0 {
		_ = os.MkdirAll(filepath.Dir(options.KRIEOptions.Output), 0644)
	}

	// check if the provided vmlinux exists
	if len(options.KRIEOptions.VMLinux) > 0 {
		_, err = os.Stat(options.KRIEOptions.VMLinux)
		if err != nil {
			return fmt.Errorf("couldn't find vmlinux: %w", err)
		}
	}
	return nil
}

func krieCmd(cmd *cobra.Command, args []string) error {
	if err := parseConfig(); err != nil {
		return err
	}
	// Set log level
	logrus.SetLevel(logrus.Level(options.KRIEOptions.LogLevel))

	// create a new KRIE instance
	trace, err := krie.NewKRIE(options.KRIEOptions)
	if err != nil {
		return fmt.Errorf("couldn't create a new instance of KRIE: %w", err)
	}

	if err := trace.Start(); err != nil {
		return fmt.Errorf("couldn't start: %w", err)
	}

	wait()

	_ = trace.Stop()
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
