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
	"github.com/mailru/easyjson/jwriter"
)

const (
	// KRIEUID is the UID used to uniquely identify kernel space programs
	KRIEUID = "krie"
)

// EventType describes the type of an event sent from the kernel
type EventType uint32

const (
	// UnknownEventType unknow event
	UnknownEventType EventType = iota
	// InitModuleEventType is the event type of an init module event
	InitModuleEventType
	// DeleteModuleEventType is the event type of a delete module event
	DeleteModuleEventType
	// MaxEventType is used internally to get the maximum number of events.
	MaxEventType
)

func (t EventType) String() string {
	switch t {
	case InitModuleEventType:
		return "init_module"
	case DeleteModuleEventType:
		return "delete_module"
	default:
		return fmt.Sprintf("EventType(%d)", t)
	}
}

// AllProbesSelectors returns all the probes selectors
func AllProbesSelectors() []manager.ProbesSelector {
	all := []manager.ProbesSelector{
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "tracepoint/raw_syscalls/sys_exit", EBPFFuncName: "sys_exit"}},
			},
		},
	}
	addAllKernelModuleProbesSelectors(&all)
	return all
}

// AllProbes returns all the probes
func AllProbes() []*manager.Probe {
	all := []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "tracepoint/raw_syscalls/sys_exit",
				EBPFFuncName: "sys_exit",
			},
		},
	}
	addKernelModuleProbes(&all)

	return all
}

// AllTailCallRoutes returns all the tail call routes
func AllTailCallRoutes() []manager.TailCallRoute {
	var all []manager.TailCallRoute
	addKernelModuleTailCallRoutes(&all)
	return all
}

// Event is used to parse the events sent from kernel space
type Event struct {
	Kernel  KernelEvent    `json:"event"`
	Process ProcessContext `json:"process"`

	InitModule   InitModule `json:"init_module"`
	DeleteModule DeleteModule
}

// NewEvent returns a new Event instance
func NewEvent() *Event {
	return &Event{}
}

func (e *Event) MarshalJSON() ([]byte, error) {
	s := NewEventSerializer(e)
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	s.MarshalEasyJSON(w)
	return w.BuildBytes()
}

func (e Event) String() string {
	data, err := e.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("failed to marshall event: %v", err)
	}
	return string(data)
}

// EventSerializer is used to serialize Event
// easyjson:json
type EventSerializer struct {
	*KernelEventSerializer    `json:"event,omitempty"`
	*ProcessContextSerializer `json:"process,omitempty"`

	*InitModuleSerializer   `json:"init_module,omitempty"`
	*DeleteModuleSerializer `json:"delete_module,omitempty"`
}

// NewEventSerializer returns a new EventSerializer instance for the provided Event
func NewEventSerializer(event *Event) *EventSerializer {
	serializer := &EventSerializer{
		KernelEventSerializer:    NewKernelEventSerializer(&event.Kernel),
		ProcessContextSerializer: NewProcessContextSerializer(&event.Process),
	}

	switch event.Kernel.Type {
	case InitModuleEventType:
		serializer.InitModuleSerializer = NewInitModuleSerializer(&event.InitModule)
	case DeleteModuleEventType:
		serializer.DeleteModuleSerializer = NewDeleteModuleSerializer(&event.DeleteModule)
	}
	return serializer
}
