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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/bpf"
)

var BPFFilter = &cobra.Command{
	Use:   "bpf-filter",
	Short: "Create a test BPF filter",
}

var Start = &cobra.Command{
	Use:   "start",
	Short: "Attach and run the DNS BPF filter",
	RunE:  startBPFFilterCmd,
}

func init() {
	BPFFilter.AddCommand(Start)
}

func startBPFFilterCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	if os.Getuid() > 0 {
		return fmt.Errorf("ktool needs to run as root")
	}

	rawSocket, err := afpacket.NewTPacket(
		afpacket.OptPollTimeout(1*time.Second),
		// This setup will require ~4Mb that is mmap'd into the process virtual space
		// More information here: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(4096*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return fmt.Errorf("error creating raw socket: %s", err)
	}
	defer rawSocket.Close()

	bpfFilter, err := generateBPFFilter()
	if err != nil {
		return fmt.Errorf("couldn't generate BPF filter: %w", err)
	}

	err = rawSocket.SetBPF(bpfFilter)
	if err != nil {
		return fmt.Errorf("error setting classic bpf filter: %w", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, os.Kill)

	logrus.Infof("DNS BPF filter running ...")
	for {
		// allow the read loop to be prematurely interrupted
		select {
		case <-done:
			return nil
		default:
		}

		for {
			_, stats, err := rawSocket.ZeroCopyReadPacketData()

			// Immediately retry for EAGAIN
			if err == syscall.EAGAIN {
				continue
			}

			if err == afpacket.ErrTimeout {
				break
			}

			logrus.Printf("captured %d bytes from interface %d", stats.Length, stats.InterfaceIndex)
		}

		time.Sleep(1 * time.Second)
	}
}

func generateBPFFilter() ([]bpf.RawInstruction, error) {
	const dnsPort = 53
	return bpf.Assemble([]bpf.Instruction{
		// (000) ldh      [12] -- load Ethertype
		bpf.LoadAbsolute{Size: 2, Off: 12},
		// (001) jeq      #0x86dd          jt 2	jf 9 -- if IPv6, goto 2, else 9
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 7},
		// (002) ldb      [20] -- load IPv6 Next Header
		bpf.LoadAbsolute{Size: 1, Off: 20},
		// (003) jeq      #0x6             jt 5	jf 4 -- IPv6 Next Header: if TCP, goto 5
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 1, SkipFalse: 0},
		// (004) jeq      #0x11            jt 5	jf 21 -- IPv6 Next Header: if UDP, goto 5, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 0, SkipFalse: 16},
		// (005) ldh      [54] -- load source port
		bpf.LoadAbsolute{Size: 2, Off: 54},
		// (006) jeq      #0x35            jt 20	jf 7 -- if 53, capture
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 13, SkipFalse: 0},
		// (007) ldh      [56] -- load dest port
		bpf.LoadAbsolute{Size: 2, Off: 56},
		// (008) jeq      #0x35            jt 20	jf 21 -- if allowedDestPort, capture, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 11, SkipFalse: 12},
		// (009) jeq      #0x800           jt 10	jf 21 -- if IPv4, go next, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 11},
		// (010) ldb      [23] -- load IPv4 Protocol
		bpf.LoadAbsolute{Size: 1, Off: 23},
		// (011) jeq      #0x6             jt 13	jf 12 -- if TCP, goto 13
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 1, SkipFalse: 0},
		// (012) jeq      #0x11            jt 13	jf 21 -- if UDP, goto 13, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 0, SkipFalse: 8},
		// (013) ldh      [20] -- load Fragment Offset
		bpf.LoadAbsolute{Size: 2, Off: 20},
		// (014) jset     #0x1fff          jt 21	jf 15 -- use 0x1fff as mask for fragment offset, if != 0, drop
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},
		// (015) ldxb     4*([14]&0xf) -- x = IP header length
		bpf.LoadMemShift{Off: 14},
		// (016) ldh      [x + 14] -- load source port
		bpf.LoadIndirect{Size: 2, Off: 14},
		// (017) jeq      #0x35            jt 20	jf 18 -- if port 53 capture
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 2, SkipFalse: 0},
		// (018) ldh      [x + 16] -- load dest port
		bpf.LoadIndirect{Size: 2, Off: 16},
		// (019) jeq      #0x35            jt 20	jf 21 -- if port allowedDestPort capture, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 0, SkipFalse: 1},
		// (020) ret      #262144 -- capture
		bpf.RetConstant{Val: 262144},
		// (021) ret      #0 -- drop
		bpf.RetConstant{Val: 0},
	})
}
