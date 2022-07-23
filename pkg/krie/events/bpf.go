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

const (
	// BPFObjectNameLen is the maximum length of a map or program name
	BPFObjectNameLen = 16
	// BPFTagLen is the length of a bpf program tag
	BPFTagLen = 8
)

func addBPFProbes(all *[]*manager.Probe) {
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/check_helper_call",
				EBPFFuncName: "kprobe_check_helper_call",
			},
			MatchFuncName: "check_helper_call",
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/security_bpf_prog",
				EBPFFuncName: "kprobe_security_bpf_prog",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/security_bpf_map",
				EBPFFuncName: "kprobe_security_bpf_map",
			},
		},
	}...)
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "bpf",
	}, EntryAndExit)...)
}

func addBPFTailCallRoutes(all *[]manager.TailCallRoute) {
	*all = append(*all, []manager.TailCallRoute{
		{
			ProgArrayName: "sys_exit_progs",
			Key:           uint32(BPFEventType),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "tracepoint/handle_sys_bpf_exit",
				EBPFFuncName: "tracepoint_handle_sys_bpf_exit",
			},
		},
	}...)
}

func addBPFProbesSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.BestEffort{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/check_helper_call", EBPFFuncName: "kprobe_check_helper_call"}},
			},
		},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/security_bpf_prog", EBPFFuncName: "kprobe_security_bpf_prog"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/security_bpf_map", EBPFFuncName: "kprobe_security_bpf_map"}},
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "bpf"}, EntryAndExit),
		},
	)
}

// BPFEvent represents a BPF event
type BPFEvent struct {
	Map     BPFMap
	Program BPFProgram
	Cmd     BPFCmd
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *BPFEvent) UnmarshallBinary(data []byte) (int, error) {
	var cursor int
	read, err := e.Map.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read
	read, err = e.Program.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	if len(data) < cursor+4 {
		return 0, fmt.Errorf("while parsing BPFEvent, got len %d, needed %d: %w", len(data), cursor+4, ErrNotEnoughData)
	}
	e.Cmd = BPFCmd(ByteOrder.Uint32(data[cursor : cursor+4]))
	return cursor + 4, nil
}

// BPFMap represents a BPF map
type BPFMap struct {
	ID   uint32     `json:"id"`
	Type BPFMapType `json:"type,omitempty"`
	Name string     `json:"name,omitempty"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (m *BPFMap) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8+BPFObjectNameLen {
		return 0, fmt.Errorf("while parsing BPFMap, got len %d, needed %d: %w", len(data), 24, ErrNotEnoughData)
	}

	m.ID = ByteOrder.Uint32(data[0:4])
	m.Type = BPFMapType(ByteOrder.Uint32(data[4:8]))

	var err error
	m.Name, err = UnmarshalString(data[8:8+BPFObjectNameLen], BPFObjectNameLen)
	if err != nil {
		return 0, err
	}
	return 8 + BPFObjectNameLen, nil
}

// BPFProgram represents a BPF program
type BPFProgram struct {
	ID         uint32            `json:"id"`
	Type       BPFProgramType    `json:"type,omitempty"`
	AttachType BPFAttachType     `json:"attach_type,omitempty"`
	Helpers    BPFHelperFuncList `json:"helpers,omitempty"`
	Name       string            `json:"name,omitempty"`
	Tag        string            `json:"tag,omitempty"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (p *BPFProgram) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 64 {
		return 0, ErrNotEnoughData
	}
	p.ID = ByteOrder.Uint32(data[0:4])
	p.Type = BPFProgramType(ByteOrder.Uint32(data[4:8]))
	p.AttachType = BPFAttachType(ByteOrder.Uint32(data[8:12]))
	// padding
	helpers := []uint64{0, 0, 0}
	helpers[0] = ByteOrder.Uint64(data[16:24])
	helpers[1] = ByteOrder.Uint64(data[24:32])
	helpers[2] = ByteOrder.Uint64(data[32:40])
	p.Helpers = parseHelpers(helpers)

	var err error
	p.Name, err = UnmarshalString(data[40:40+BPFObjectNameLen], BPFObjectNameLen)
	if err != nil {
		return 0, err
	}
	for _, b := range data[40+BPFObjectNameLen : 40+BPFObjectNameLen+BPFTagLen] {
		p.Tag += fmt.Sprintf("%x", b)
	}
	return 40 + BPFObjectNameLen + BPFTagLen, nil
}

func parseHelpers(helpers []uint64) BPFHelperFuncList {
	var rep BPFHelperFuncList
	var add bool

	if len(helpers) < 3 {
		return rep
	}

	for i := 0; i < 192; i++ {
		add = false
		if i < 64 {
			if helpers[0]&(1<<i) == (1 << i) {
				add = true
			}
		} else if i < 128 {
			if helpers[1]&(1<<(i-64)) == (1 << (i - 64)) {
				add = true
			}
		} else if i < 192 {
			if helpers[2]&(1<<(i-128)) == (1 << (i - 128)) {
				add = true
			}
		}

		if add {
			rep = append(rep, BPFHelperFunc(i))
		}
	}
	return rep
}

// BPFEventSerializer is used to serialize BPFEvent
// easyjson:json
type BPFEventSerializer struct {
	Map     *BPFMap     `json:"map,omitempty"`
	Program *BPFProgram `json:"program,omitempty"`
	Cmd     BPFCmd      `json:"cmd"`
}

// NewBPFEventSerializer returns a new instance of BPFEventSerializer
func NewBPFEventSerializer(e *BPFEvent) *BPFEventSerializer {
	serializer := &BPFEventSerializer{
		Cmd: e.Cmd,
	}

	if e.Program.ID > 0 {
		serializer.Program = &e.Program
	}
	if e.Map.ID > 0 {
		serializer.Map = &e.Map
	}
	return serializer
}

// BPFFilterEvent represents a BPF event
type BPFFilterEvent struct {
	Cmd      BPFFilterCmd  `json:"cmd,omitempty"`
	Family   AddressFamily `json:"family,omitempty"`
	Type     SocketType    `json:"type,omitempty"`
	Protocol L3Protocol    `json:"protocol,omitempty"`
	ProgLen  uint16        `json:"prog_len,omitempty"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *BPFFilterEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, fmt.Errorf("while parsing BPFFilterEvent, got len %d, needed %d: %w", len(data), 16, ErrNotEnoughData)
	}
	e.Family = AddressFamily(ByteOrder.Uint16(data[0:2]))
	e.Type = SocketType(ByteOrder.Uint16(data[2:4]))
	e.Protocol = L3Protocol(ByteOrder.Uint16(data[4:6]))
	e.ProgLen = ByteOrder.Uint16(data[6:8])
	e.Cmd = BPFFilterCmd(ByteOrder.Uint32(data[8:12]))
	// padding 4 bytes
	return 16, nil
}

// BPFFilterEventSerializer is used to serialize BPFFilterEvent
// easyjson:json
type BPFFilterEventSerializer struct {
	*BPFFilterEvent
}

// NewBPFFilterEventSerializer returns a new instance of BPFFilterEventSerializer
func NewBPFFilterEventSerializer(e *BPFFilterEvent) *BPFFilterEventSerializer {
	serializer := &BPFFilterEventSerializer{
		BPFFilterEvent: e,
	}
	return serializer
}
