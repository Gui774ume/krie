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

type KernelParameter struct {
	Address       uint64
	ExpectedValue uint64
	LastSent      uint64
	Size          uint64
}

func kernelParameterFromParameterOption(po events.ParameterOption) *KernelParameter {
	return &KernelParameter{
		Address:       po.Address,
		ExpectedValue: po.ExpectedValue,
		Size:          po.Size,
	}
}

func (e *KRIE) loadKernelParameters() error {
	for key, param := range e.options.Events.KernelParameterEvent.List {
		if param.Address == 0 {
			if len(param.Symbol) == 0 {
				return fmt.Errorf("couldn't load kernel parameters: an address or a symbol must be provided for each parameter: %+v", param)
			}
			address, ok := e.kernelSymbols[param.Symbol]
			if !ok {
				return fmt.Errorf("couldn't find %s kernel parameter", param.Symbol)
			}
			param.Address = address.Value
		}

		if err := e.kernelParametersMap.Put(uint32(key), kernelParameterFromParameterOption(param)); err != nil {
			return fmt.Errorf("couldn't push %s kernel parameter: %w", param.Symbol, err)
		}
	}
	return nil
}
