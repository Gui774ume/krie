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

// KernelParameterOptions is used to configure the kernel_parameter events
type KernelParameterOptions struct {
	Action         Action `yaml:"action"`
	PeriodicAction Action `yaml:"periodic_action"`
	Ticker         int64  `yaml:"ticker"`
}

// NewKernelParameterOptions returns a new instance of KernelParameterOptions
func NewKernelParameterOptions() *KernelParameterOptions {
	return &KernelParameterOptions{}
}
