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

// SymbolNameLength is the length of the name of a kernel symbol
const SymbolNameLength = 64

func addKProbeProbes(all *[]*manager.Probe) {
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/register_kprobe",
				EBPFFuncName: "kprobe_register_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kretprobe/register_kprobe",
				EBPFFuncName: "kretprobe_register_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/register_kretprobe",
				EBPFFuncName: "kprobe_register_kretprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/enable_kprobe",
				EBPFFuncName: "kprobe_enable_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kretprobe/enable_kprobe",
				EBPFFuncName: "kretprobe_enable_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/disable_kprobe",
				EBPFFuncName: "kprobe_disable_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kretprobe/disable_kprobe",
				EBPFFuncName: "kretprobe_disable_kprobe",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/__unregister_kprobe_top",
				EBPFFuncName: "kprobe___unregister_kprobe_top",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kretprobe/__unregister_kprobe_top",
				EBPFFuncName: "kretprobe___unregister_kprobe_top",
			},
		},
	}...)
}

func addKProbeRoutes(all *[]manager.TailCallRoute) {}

func addKProbeSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/register_kprobe", EBPFFuncName: "kprobe_register_kprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kretprobe/register_kprobe", EBPFFuncName: "kretprobe_register_kprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/register_kretprobe", EBPFFuncName: "kprobe_register_kretprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/__unregister_kprobe_top", EBPFFuncName: "kprobe___unregister_kprobe_top"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kretprobe/__unregister_kprobe_top", EBPFFuncName: "kretprobe___unregister_kprobe_top"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/enable_kprobe", EBPFFuncName: "kprobe_enable_kprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kretprobe/enable_kprobe", EBPFFuncName: "kretprobe_enable_kprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/disable_kprobe", EBPFFuncName: "kprobe_disable_kprobe"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kretprobe/disable_kprobe", EBPFFuncName: "kretprobe_disable_kprobe"}},
	)
}

// KProbeEvent represents a ptrace event
type KProbeEvent struct {
	Address MemoryPointer `json:"address,omitempty"`
	Symbol  string        `json:"string,omitempty"`
	Command KProbeCommand `json:"command"`
	Type    KProbeType    `json:"type"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *KProbeEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < SymbolNameLength+16 {
		return 0, fmt.Errorf("while parsing KProbeEvent, got len %d, needed %d: %w", len(data), SymbolNameLength+8, ErrNotEnoughData)
	}
	e.Address = MemoryPointer(ByteOrder.Uint64(data[0:8]))
	e.Command = KProbeCommand(ByteOrder.Uint32(data[8:12]))
	e.Type = KProbeType(ByteOrder.Uint32(data[12:16]))

	var err error
	e.Symbol, err = UnmarshalString(data[16:16+SymbolNameLength], SymbolNameLength)
	if err != nil {
		return 0, err
	}
	return SymbolNameLength + 16, nil
}

// KProbeEventSerializer is used to serialize KProbeEvent
// easyjson:json
type KProbeEventSerializer struct {
	*KProbeEvent
}

// NewKProbeEventSerializer returns a new instance of KProbeEventSerializer
func NewKProbeEventSerializer(e *KProbeEvent) *KProbeEventSerializer {
	return &KProbeEventSerializer{
		KProbeEvent: e,
	}
}
