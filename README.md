## KRIE

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

KRIE is a syscall tracing utility powered by eBPF.

This is (yet another) `strace` implementation with a twist:
- KRIE figures out dynamically the parameters of each syscall by parsing the tracepoint format files in the `/sys/kernel/debug/tracing/events/syscalls/*` directories
- KRIE fetches dynamically the size of each structure of each syscall parameter by parsing the BTF information of the kernel. Once the data is retrieved from kernel space, it uses the same BTF information to parse and format the captured data.

In addition to normal syscall parameters, KRIE also collects process context data on each syscall entry and exit. This context includes:
- The process cgroups
- The process namespaces
- The process credentials
- The process comm

### System requirements

This project was developed on a Ubuntu Hirsute machine (Linux Kernel 5.11).

- golang 1.16+
- (optional) Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- (optional) clang & llvm 11.0.1+
- (optional) libbpf-dev

Optional fields are required to recompile the eBPF programs.

### Build

1) Since KRIE was built using CORE, you shouldn't need to rebuild the eBPF programs. That said, if you want to rebuild the eBPF programs, you can use the following command:

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

KRIE needs to run as root. Run `sudo krie -h` to get help.

```shell script
# ~ krie -h
Usage:
  krie [flags]

Flags:
      --bytes int             amount of bytes shown to the screen when --stdout is provided (default 8)
  -c, --comm stringArray      list of process comms to filter, leave empty to capture everything
  -h, --help                  help for krie
      --input string          input file to parse data from
      --json                  parse and dump the data retrieved from kernel space in the JSON format. This option might lead to more lost events than the --raw option and more CPU usage
  -l, --log-level string      log level, options: panic, fatal, error, warn, info, debug or trace (default "info")
      --raw                   dump the data retrieved from kernel space without parsing it, use this option instead of the --json option to reduce the amount of lost events, and reduce the CPU usage of KRIE. You can ask KRIE to parse a --raw dump using the --input option
      --stats                 show syscall statistics (default true)
      --stdout                parse and dump the data retrieved from kernel space to the console. This option might lead to more lost events than the --raw option and more CPU usage.
  -s, --syscall stringArray   list of syscalls to filter, leave empty to capture everything
```

### Example

#### Dump all the syscalls of the command `cat /etc/hosts`

```shell script
# ~ sudo krie --comm cat --stdout
INFO[2021-09-25T21:54:11Z] Tracing started ... (Ctrl + C to stop)
cat(10609) | SysBrk(unsigned long brk: 0) = 93940710199296
cat(10609) | SysArchPrctl(int option: 12289, unsigned long arg2: 140727494090368) = -22
cat(10609) | SysAccess(const char * filename: /etc/ld.so.preload, int mode: 4) = -2
cat(10609) | SysOpenat(int dfd: 4294967196, const char * filename: /etc/ld.so.cache, int flags: 524288, umode_t mode: 0) = 3
cat(10609) | SysNewfstatat(int dfd: 3, const char * filename: NULL, struct stat * statbuf: {uint st_dev: 2049, uint st_ino: 1988, uint st_nlink: 1, uint st_mode: 33188, uint st_uid: 0, uint st_gid: 0, uint __pad0: 0, uint st_rdev: 0, int st_size: 34082, int st_blksize: 4096, int st_blocks: 72, uint st_atime: 1632575756, uint st_atime_nsec: 340000086, uint st_mtime: 1632478351, uint st_mtime_nsec: 721952010, uint st_ctime: 1632478351, uint st_ctime_nsec: 721952010, array __unused: {int 0: 0, int 1: 0, int 2: 0}}, int flag: 4096) = 0
cat(10609) | SysMmap(unsigned long addr: 0, unsigned long len: 34082, unsigned long prot: 1, unsigned long flags: 2, unsigned long fd: 3, unsigned long off: 0) = 140402711691264
cat(10609) | SysClose(unsigned int fd: 3) = 0
cat(10609) | SysOpenat(int dfd: 4294967196, const char * filename: /lib/x86_64-linux-gnu/libc.so.6, int flags: 524288, umode_t mode: 0) = 3
cat(10609) | SysRead(unsigned int fd: 3, char * buf: 0x7f454c4602010103..., size_t count: 832) = 832
cat(10609) | SysPread64(unsigned int fd: 3, char * buf: 0x0600000004000000..., size_t count: 784, loff_t pos: 64) = 784
cat(10609) | SysPread64(unsigned int fd: 3, char * buf: 0x0400000020000000..., size_t count: 48, loff_t pos: 848) = 48
cat(10609) | SysPread64(unsigned int fd: 3, char * buf: 0x0400000014000000..., size_t count: 68, loff_t pos: 896) = 68
[...]
cat(10609) | SysOpenat(int dfd: 4294967196, const char * filename: /etc/hosts, int flags: 0, umode_t mode: 0) = 3
cat(10609) | SysFstat(unsigned int fd: 3, struct stat * statbuf: {uint st_dev: 2049, uint st_ino: 44, uint st_nlink: 1, uint st_mode: 33188, uint st_uid: 0, uint st_gid: 0, uint __pad0: 0, uint st_rdev: 0, int st_size: 262, int st_blksize: 4096, int st_blocks: 8, uint st_atime: 1632575760, uint st_atime_nsec: 904000225, uint st_mtime: 1627389290, uint st_mtime_nsec: 284000207, uint st_ctime: 1627389290, uint st_ctime_nsec: 284000207, array __unused: {int 0: 0, int 1: 0, int 2: 0}}) = 0
cat(10609) | SysFadvise64(int fd: 3, loff_t offset: 0, size_t len: 0, int advice: 2) = 0
cat(10609) | SysMmap(unsigned long addr: 0, unsigned long len: 139264, unsigned long prot: 3, unsigned long flags: 34, unsigned long fd: 4294967295, unsigned long off: 0) = 140402704576512
cat(10609) | SysRead(unsigned int fd: 3, char * buf: 127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	ip6-localhost	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
ff02::3	ip6-allhosts
127.0.1.1	ubuntu-hirsute	ubuntu-hirsute

, size_t count: 131072) = 262
cat(10609) | SysWrite(unsigned int fd: 1, const char * buf: 127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	ip6-localhost	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
ff02::3	ip6-allhosts
127.0.1.1	ubuntu-hirsute	ubuntu-hirsute

, size_t count: 262) = 262
cat(10609) | SysRead(unsigned int fd: 3, char * buf: NULL, size_t count: 131072) = 0
cat(10609) | SysMunmap(unsigned long addr: 140402704576512, size_t len: 139264) = 0
cat(10609) | SysClose(unsigned int fd: 3) = 0
cat(10609) | SysClose(unsigned int fd: 1) = 0
cat(10609) | SysClose(unsigned int fd: 2) = 0
```

## License

- The golang code is under Apache 2.0 License.
- The eBPF programs are under the GPL v2 License.