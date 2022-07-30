all: build-ebpf build-ebpf-syscall-wrapper generate build install

build-ebpf:
	mkdir -p ebpf/bin
	clang-14 -D__KERNEL__ -DCONFIG_64BIT -D__ASM_SYSREG_H -D__x86_64__ -D__BPF_TRACING__ -DKBUILD_MODNAME=\"krie\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o ebpf/bin/probe.o

build-ebpf-syscall-wrapper:
	mkdir -p ebpf/bin
	clang-14 -D__KERNEL__ -DCONFIG_64BIT -D__ASM_SYSREG_H -D__x86_64__ -DUSE_SYSCALL_WRAPPER=1 -D__BPF_TRACING__ -DKBUILD_MODNAME=\"krie\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o ebpf/bin/probe_syscall_wrapper.o

generate:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -prefix "ebpf/bin" -o "pkg/assets/probe.go" "ebpf/bin/probe_syscall_wrapper.o" "ebpf/bin/probe.o"

generate-serializer:
	go generate ./...

build:
	mkdir -p bin/
	go build -o bin/ ./cmd/...

run:
	sudo ./bin/krie --log-level debug

install:
	sudo cp ./bin/* /usr/bin/
	sudo chmod aog+x /usr/bin/krie
	sudo chmod aog+x /usr/bin/ktool
