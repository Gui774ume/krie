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

package krie

import (
	"fmt"

	"github.com/Gui774ume/krie/pkg/krie/events"
)

type SysCtlParameter struct {
	BlockWriteAccess       bool   `yaml:"block_write_access"`
	BlockReadAccess        bool   `yaml:"block_read_access"`
	OverrideInputValueWith string `yaml:"override_input_value_with"`
}

// MarshalBinary returns a binary representation of itself
func (scp SysCtlParameter) MarshalBinary() ([]byte, error) {
	b := make([]byte, 264)
	events.ByteOrder.PutUint32(b[0:4], uint32(len(scp.OverrideInputValueWith)))
	if scp.BlockWriteAccess {
		events.ByteOrder.PutUint16(b[4:6], 1)
	}
	if scp.BlockReadAccess {
		events.ByteOrder.PutUint16(b[6:8], 1)
	}
	if len(scp.OverrideInputValueWith) > 0 {
		copy(b[8:264], scp.OverrideInputValueWith)
	}
	return b, nil
}

func (e *KRIE) loadSysCtlParameters() error {
	// load parameters
	for name, param := range e.options.SysCtlParameters {
		b := make([]byte, 256)
		copy(b, name)
		if err := e.sysctlParameters.Put(b, &param); err != nil {
			return fmt.Errorf("failed to push SysCtlParameter for %s: %w", name, err)
		}
	}

	// load defaults
	key := uint32(0)
	if err := e.sysctlDefault.Put(key, &e.options.SysCtlDefault); err != nil {
		return fmt.Errorf("failed to push default SysCtlParameter: %w", err)
	}
	return nil
}
