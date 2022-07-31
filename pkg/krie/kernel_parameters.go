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
)

type KernelParameter struct {
	Address       uint64
	ExpectedValue uint64
	LastSent      uint64
	Size          uint64
}

var (
	kernerlParameters = []struct {
		Symbol    string
		Parameter *KernelParameter
	}{
		{
			Symbol: "system/ftrace_enabled",
			Parameter: &KernelParameter{
				ExpectedValue: 1,
				Size:          4,
			},
		},
		{
			Symbol: "system/kprobes_all_disarmed",
			Parameter: &KernelParameter{
				ExpectedValue: 0,
				Size:          4,
			},
		},
	}
)

func (e *KRIE) loadKernelParameters() error {
	for key, param := range kernerlParameters {
		address, ok := e.kernelSymbols[param.Symbol]
		if !ok {
			return fmt.Errorf("couldn't find %s kernel parameter", param.Symbol)
		}
		param.Parameter.Address = address.Value
		if err := e.kernelParametersMap.Put(uint32(key), param.Parameter); err != nil {
			return fmt.Errorf("couldn't push %s kernel parameter: %w", param.Symbol, err)
		}
	}
	return nil
}
