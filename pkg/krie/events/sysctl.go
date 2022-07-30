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

//go:generate go run github.com/mailru/easyjson/easyjson -no_std_marshalers $GOFILE

package events

import (
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
)

func addSysCtlProbes(all *[]*manager.Probe) {
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "cgroup/sysctl",
				EBPFFuncName: "cgroup_sysctl",
			},
			CGroupPath: "/sys/fs/cgroup/unified",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/proc_sys_call_handler",
				EBPFFuncName: "kprobe_proc_sys_call_handler",
			},
		},
	}...)
}

func addSysCtlRoutes(all *[]manager.TailCallRoute) {
	*all = append(*all, []manager.TailCallRoute{}...)
}

func addSysCtlSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "cgroup/sysctl", EBPFFuncName: "cgroup_sysctl"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/proc_sys_call_handler", EBPFFuncName: "kprobe_proc_sys_call_handler"}},
	)
}

// SysCtlEvent represents a ptrace event
type SysCtlEvent struct {
	WriteAccess            bool         `json:"write_access"`
	FilePosition           uint32       `json:"file_position"`
	Action                 SysCtlAction `json:"action"`
	Name                   string       `json:"name"`
	CurrentValue           string       `json:"current_value"`
	NewValue               string       `json:"new_value,omitempty"`
	NewValueOverriddenWith string       `json:"new_value_overridden_with,omitempty"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *SysCtlEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, fmt.Errorf("while parsing SysCtlEvent, got len %d, needed %d: %w", len(data), 16, ErrNotEnoughData)
	}
	if ByteOrder.Uint32(data[0:4]) == 1 {
		e.WriteAccess = true
	}
	e.FilePosition = ByteOrder.Uint32(data[4:8])
	e.Action = SysCtlAction(ByteOrder.Uint64(data[8:16]))
	cursor := 16

	// parse name, current_value and new_value
	if len(data[cursor:]) > 0 {
		var err error
		e.Name, err = UnmarshalString(data[cursor:], len(data[cursor:]))
		if err != nil {
			return 0, fmt.Errorf("while parsing SysCtlEvent.Name, got len %d, needed %d: %w", len(data[cursor:]), 256, ErrNotEnoughData)
		}
		cursor += len(e.Name) + 1

		if len(data[cursor:]) > 0 {
			e.CurrentValue, err = UnmarshalString(data[cursor:], len(data[cursor:]))
			if err != nil {
				return 0, fmt.Errorf("while parsing SysCtlEvent.CurrentValue, got len %d, needed %d: %w", len(data[cursor:]), 256, ErrNotEnoughData)
			}
			cursor += len(e.CurrentValue) + 1

			if len(data[cursor:]) > 0 {
				e.NewValue, err = UnmarshalString(data[cursor:], len(data[cursor:]))
				if err != nil {
					return 0, fmt.Errorf("while parsing SysCtlEvent.NewValue, got len %d, needed %d: %w", len(data[cursor:]), 256, ErrNotEnoughData)
				}
				cursor += len(e.NewValue) + 1
			}
		}
	}

	return 16 + cursor, nil
}

// SysCtlEventEventSerializer is used to serialize SysCtlEvent
// easyjson:json
type SysCtlEventEventSerializer struct {
	*SysCtlEvent
}

// NewSysCtlEventSerializer returns a new instance of PtraceEventSerializer
func NewSysCtlEventSerializer(e *SysCtlEvent) *SysCtlEventEventSerializer {
	return &SysCtlEventEventSerializer{
		SysCtlEvent: e,
	}
}

type SysCtlParameter struct {
	BlockWriteAccess       bool   `yaml:"block_write_access"`
	BlockReadAccess        bool   `yaml:"block_read_access"`
	OverrideInputValueWith string `yaml:"override_input_value_with"`
}

// MarshalBinary returns a binary representation of itself
func (scp SysCtlParameter) MarshalBinary() ([]byte, error) {
	b := make([]byte, 264)
	ByteOrder.PutUint32(b[0:4], uint32(len(scp.OverrideInputValueWith)))
	if scp.BlockWriteAccess {
		ByteOrder.PutUint16(b[4:6], 1)
	}
	if scp.BlockReadAccess {
		ByteOrder.PutUint16(b[6:8], 1)
	}
	if len(scp.OverrideInputValueWith) > 0 {
		copy(b[8:264], scp.OverrideInputValueWith)
	}
	return b, nil
}

type SysCtlOptions struct {
	Action  Action                     `yaml:"action"`
	Default SysCtlParameter            `yaml:"default"`
	List    map[string]SysCtlParameter `yaml:"list"`
}

// NewSysCtlOptions returns a new instance of SysCtlOptions
func NewSysCtlOptions() *SysCtlOptions {
	return &SysCtlOptions{
		List: make(map[string]SysCtlParameter),
	}
}
