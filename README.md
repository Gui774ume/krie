## KRIe

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

KRIe is a research project that aims to detect Linux Kernel exploits with eBPF. KRIe is far from being a bulletproof strategy: from eBPF related limitations to post exploitation detections that might rely on a compromised kernel to emit security events, it is clear that a motivated attacker will eventually be able to bypass it.
That being said, the goal of the project is to make attackers' lives harder and ultimately prevent out-of-the-box exploits from working on a vulnerable kernel.

KRIe has been developed using [CO-RE (Compile Once - Run Everywhere)](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) so that it is compatible with a large range of kernel versions. If your kernel doesn't export its BTF debug information, KRIe will try to download it automatically from [BTFHub](https://github.com/aquasecurity/btfhub). If your kernel isn't available on BTFHub, but you have been able to manually generate your kernel's BTF data, you can provide it in the configuration file (see below).

### System requirements

This project was developed on Ubuntu Focal 20.04 (Linux Kernel 5.15) and has been tested on older releases down to Ubuntu Bionic 18.04 (Linux Kernel 4.15).

- golang 1.18+
- (optional) Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- (optional) clang & llvm 14.0.6+

Optional fields are required to recompile the eBPF programs.

### Build

1) Since KRIe was built using CORE, you shouldn't need to rebuild the eBPF programs. That said, if you want still want to rebuild the eBPF programs, you can use the following command:

```shell script
# ~ make build-ebpf
```

2) To build KRIE, run:

```shell script
# ~ make build
```

3) To install KRIE (copy to /usr/bin/krie) run:
```shell script
# ~ make install
```

### Getting started

KRIe needs to run as root. Run `sudo krie -h` to get help.

```shell script
# ~ krie -h
Usage:
  krie [flags]

Flags:
      --config string   KRIe config file (default "./cmd/krie/run/config/default_config.yaml")
  -h, --help            help for krie
```

### Configuration

```yaml
## Log level, options are: panic, fatal, error, warn, info, debug or trace
log_level: debug

## JSON output file, leave empty to disable JSON output.
output: "/tmp/krie.json"

## BTF information for the current kernel in .tar.xz format (required only if KRIE isn't able to locate it by itself)
vmlinux: ""

## events configuration
events:
  ## action taken when an init_module event is detected
  init_module: log

  ## action taken when an delete_module event is detected
  delete_module: log

  ## action taken when a bpf event is detected
  bpf: log

  ## action taken when a bpf_filter event is detected
  bpf_filter: log

  ## action taken when a ptrace event is detected
  ptrace: log

  ## action taken when a kprobe event is detected
  kprobe: log

  ## action taken when a sysctl event is detected
  sysctl:
    action: log

    ## Default settings for sysctl programs (kernel 5.2+ only)
    sysctl_default:
      block_read_access: false
      block_write_access: false

    ## Custom settings for sysctl programs (kernel 5.2+ only)
    sysctl_parameters:
      kernel/yama/ptrace_scope:
        block_write_access: true
      kernel/ftrace_enabled:
        override_input_value_with: "1\n"

  ## action taken when a hooked_syscall_table event is detected
  hooked_syscall_table: log

  ## action taken when a hooked_syscall event is detected
  hooked_syscall: log

  ## kernel_parameter event configuration
  kernel_parameter:
    action: log
    periodic_action: log
    ticker: 1 # sends at most one event every [ticker] second(s)
    list:
      - symbol: system/kprobes_all_disarmed
        expected_value: 0
        size: 4
      #      - symbol: system/selinux_state
      #        expected_value: 256
      #        size: 2

      # sysctl
      - symbol: system/ftrace_dump_on_oops
        expected_value: 0
        size: 4
      - symbol: system/kptr_restrict
        expected_value: 0
        size: 4
      - symbol: system/randomize_va_space
        expected_value: 2
        size: 4
      - symbol: system/stack_tracer_enabled
        expected_value: 0
        size: 4
      - symbol: system/unprivileged_userns_clone
        expected_value: 0
        size: 4
      - symbol: system/unprivileged_userns_apparmor_policy
        expected_value: 1
        size: 4
      - symbol: system/sysctl_unprivileged_bpf_disabled
        expected_value: 1
        size: 4
      - symbol: system/ptrace_scope
        expected_value: 2
        size: 4
      - symbol: system/sysctl_perf_event_paranoid
        expected_value: 2
        size: 4
      - symbol: system/kexec_load_disabled
        expected_value: 1
        size: 4
      - symbol: system/dmesg_restrict
        expected_value: 1
        size: 4
      - symbol: system/modules_disabled
        expected_value: 0
        size: 4
      - symbol: system/ftrace_enabled
        expected_value: 1
        size: 4
      - symbol: system/ftrace_disabled
        expected_value: 0
        size: 4
      - symbol: system/sysctl_protected_fifos
        expected_value: 1
        size: 4
      - symbol: system/sysctl_protected_hardlinks
        expected_value: 1
        size: 4
      - symbol: system/sysctl_protected_regular
        expected_value: 2
        size: 4
      - symbol: system/sysctl_protected_symlinks
        expected_value: 1
        size: 4
      - symbol: system/sysctl_unprivileged_userfaultfd
        expected_value: 0
        size: 4

  ## action to check when a register_check fails on a sensitive kernel space hook point
  register_check: log
```

## Documentation

- The first version of KRIe was announced at BlackHat 2022, during the briefing: [Return to Sender - Detecting Kernel Exploits with eBPF](https://www.blackhat.com/us-22/briefings/schedule/index.html#return-to-sender---detecting-kernel-exploits-with-ebpf-27127)

## License

- The golang code is under Apache 2.0 License.
- The eBPF programs are under the GPL v2 License.