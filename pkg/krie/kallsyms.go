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
	"debug/elf"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/lorenzosaino/go-sysctl"
	"github.com/sirupsen/logrus"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/Gui774ume/krie/pkg/krie/events"
)

func (e *KRIE) loadKernelSymbols() error {
	e.kernelSymbolsLock.Lock()
	defer e.kernelSymbolsLock.Unlock()

	// ensure we can read symbols addresses from /proc/kallsyms
	if err := e.symbolAddressesAccessCheck(); err != nil {
		return err
	}

	// load /proc/kallsyms
	if err := e.parseKallsyms(); err != nil {
		return err
	}

	// reset kernel.kptr_pointer if needed
	if err := e.resetKernelKPTRRestrict(); err != nil {
		return err
	}

	// sync kernel maps
	if err := e.pushKernelSymbols(); err != nil {
		return err
	}
	return nil
}

var (
	krieSymbols = []string{
		"system/sys_call_table",
		"system/x32_sys_call_table",
		"system/ia32_sys_call_table",
		"system/_stext",
		"system/_etext",
	}
)

func (e *KRIE) pushKernelSymbols() error {
	for key, symbol := range krieSymbols {
		address, ok := e.kernelSymbols[symbol]
		if !ok {
			return fmt.Errorf("couldn't find %s symbol", symbol)
		}
		if err := e.kallsymsMap.Put(uint32(key), &address.Value); err != nil {
			return fmt.Errorf("couldn't push %s symbol address: %w", symbol, err)
		}
	}
	return nil
}

func (e *KRIE) saveKernelKPTRRestrict(val string) {
	e.kernelKPTRRestrict = val
}

func (e *KRIE) resetKernelKPTRRestrict() error {
	if len(e.kernelKPTRRestrict) > 0 {
		logrus.Debugf("resetting kernel.kptr_pointer to %s", e.kernelKPTRRestrict)
		return e.setKernelKPTRRestrict(e.kernelKPTRRestrict)
	}
	return nil
}

func (e *KRIE) setKernelKPTRRestrict(val string) error {
	return sysctl.Set("kernel.kptr_restrict", val)
}

func (e *KRIE) symbolAddressesAccessCheck() error {
	// we need to check sysctl
	val, err := sysctl.Get("kernel.kptr_restrict")
	if err != nil {
		return fmt.Errorf("couldn't read kernel.kptr_restrict systcl parameter: %w", err)
	}

	switch val {
	case "0":
		// all good, carry on
		return nil
	case "1":
		// and the capabilities of the process
		capabilities, err := cap.GetPID(0)
		if err != nil {
			return fmt.Errorf("couldn't retrieve the kernel capabilities of the current process: %w", err)
		}

		hasCapSysLog, err := capabilities.GetFlag(cap.Effective, cap.SYSLOG)
		if err != nil {
			return fmt.Errorf("couldn't retrieve SYSLOG capability status: %w", err)
		}

		if hasCapSysLog {
			// all good, carry on
			return nil
		}

		logrus.Debugf("kernel.kptr_restric is set to 1 but the current process is missing CAP_SYSLOG, overriding kernel.kptr_restric temporarily to 0")
		e.saveKernelKPTRRestrict("1")
		return e.setKernelKPTRRestrict("0")
	case "2":
		logrus.Debugf("kernel symbol addresses are hidden, overriding kernel.kptr_restric temporarily to 0")
		e.saveKernelKPTRRestrict("2")
		return e.setKernelKPTRRestrict("0")
	default:
		return fmt.Errorf("unknown kernel.kptr_restric parameter value: \"%s\"", val)
	}
}

func (e *KRIE) parseKallsyms() error {
	kallsymsRaw, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		return err
	}

	var kallsyms []*elf.Symbol
	for _, sym := range strings.Split(string(kallsymsRaw), "\n") {
		splitSym := strings.Split(sym, " ")
		if len(splitSym) != 3 {
			continue
		}
		if splitSym[1] != "T" && splitSym[1] != "t" && splitSym[1] != "R" && splitSym[1] != "r" && splitSym[1] != "D" && splitSym[1] != "d" {
			continue
		}
		addr, err := strconv.ParseUint(splitSym[0], 16, 64)
		if err != nil {
			continue
		}
		splitName := strings.Split(splitSym[2], "\t")

		if addr == 0 {
			return fmt.Errorf("kernel addresses are hidden (address not found for %s)", splitName[0])
		}

		// do we already have this symbol in cache ?
		if _, ok := e.kernelSymbols[splitName[0]]; ok {
			continue
		}

		newSymbol := &elf.Symbol{
			Name:  splitName[0],
			Value: addr,
			Info:  uint8(elf.STT_FUNC),
		}

		if len(splitName) > 1 {
			newSymbol.Library = strings.TrimPrefix(splitName[1], "[")
			newSymbol.Library = strings.TrimSuffix(newSymbol.Library, "]")
		} else {
			newSymbol.Library = "system"
		}

		kallsyms = append(kallsyms, newSymbol)
	}

	// compute symbol sizes
	kallsymsLen := len(kallsyms)
	for i, sym := range kallsyms {
		var size uint64
		if i < kallsymsLen-1 {
			size = kallsyms[i+1].Value - sym.Value
		}
		sym.Size = size

		e.kernelAddresses[events.MemoryPointer(sym.Value)] = sym
		e.kernelSymbols[sym.Library+"/"+sym.Name] = sym
	}
	return nil
}

func (e *KRIE) resolveKernelSymbol(k *events.KernelSymbol) error {
	for symbolAddr, symbol := range e.kernelAddresses {
		if k.Address >= symbolAddr && k.Address < symbolAddr+events.MemoryPointer(symbol.Size) {
			k.Symbol = symbol.Name
			k.Module = symbol.Library
		}
	}
	k.Symbol = "unknown"
	k.Module = "unknown"
	return fmt.Errorf("couldn't resolve 0x%x", k.Address)
}
