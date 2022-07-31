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
)

// MaxKernelParameterCount is the hardcoded maximum count of kernel parameters that KRIE can check
const MaxKernelParameterCount = 1000

// KernelParameterEvent represents a kernel_parameter event
type KernelParameterEvent struct {
	Parameter     KernelSymbol `json:"parameter,omitempty"`
	ExpectedValue uint64       `json:"expected_value"`
	ActualValue   uint64       `json:"actual_value"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *KernelParameterEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 24 {
		return 0, fmt.Errorf("while parsing KernelParameterEvent, got len %d, needed %d: %w", len(data), 24, ErrNotEnoughData)
	}
	e.Parameter.Address = MemoryPointer(ByteOrder.Uint64(data[0:8]))
	e.ExpectedValue = ByteOrder.Uint64(data[8:16])
	e.ActualValue = ByteOrder.Uint64(data[16:24])
	return 24, nil
}

// KernelParameterEventSerializer is used to serialize KernelParameterEvent
// easyjson:json
type KernelParameterEventSerializer struct {
	*KernelParameterEvent
}

// NewKernelParameterEventSerializer returns a new instance of KernelParameterEventSerializer
func NewKernelParameterEventSerializer(e *KernelParameterEvent) *KernelParameterEventSerializer {
	return &KernelParameterEventSerializer{
		KernelParameterEvent: e,
	}
}

// ParameterOption is used to configure a kernel parameter that KRIE should check
type ParameterOption struct {
	Symbol        string `yaml:"symbol"`
	Address       uint64 `yaml:"address"`
	ExpectedValue uint64 `yaml:"expected_value"`
	Size          uint64 `yaml:"size"`
}

// KernelParameterOptions is used to configure the kernel_parameter events
type KernelParameterOptions struct {
	Action         Action            `yaml:"action"`
	PeriodicAction Action            `yaml:"periodic_action"`
	Ticker         int64             `yaml:"ticker"`
	List           []ParameterOption `yaml:"list"`
}

func (o KernelParameterOptions) IsValid() error {
	if len(o.List) > MaxKernelParameterCount {
		return fmt.Errorf("too many kernel parameters to check: %d > %d", len(o.List), MaxKernelParameterCount)
	}
	for _, param := range o.List {
		if len(param.Symbol) == 0 && param.Address == 0 {
			return fmt.Errorf("each parameter should have at least a symbol or an address: %+v", param)
		}
	}
	if o.PeriodicAction == BlockAction || o.PeriodicAction == KillAction {
		return fmt.Errorf("kernel_parameter.periodic_action cannot be set to \"block\" or \"kill\"")
	}
	return nil
}

// NewKernelParameterOptions returns a new instance of KernelParameterOptions
func NewKernelParameterOptions() *KernelParameterOptions {
	return &KernelParameterOptions{}
}
