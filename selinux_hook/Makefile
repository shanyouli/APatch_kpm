SELINUX_VERSION := 1.1.9.2
KP_DIR ?= ../KernelPatch
OUT_DIR ?= .
PYTHON ?= python3
CC = clang --target=aarch64-linux-gnu
LD = zig cc -target aarch64-linux-gnu
CFLAGS = -Wall -O2 -ffreestanding -fno-builtin -fno-strict-aliasing -fno-PIC \
 -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common \
 -mgeneral-regs-only -ffixed-x18 -mno-outline-atomics -std=gnu11
INCLUDE_DIRS := . include patch/include linux/include linux/security/selinux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
kpm := $(OUT_DIR)/selinux_MAF_fork_$(SELINUX_VERSION)
all: dynamic static
dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm
$(kpm)_baselines.kpm: MODE_FLAGS += -DCONFIG_KPM_BASELINES
$(kpm).kpm $(kpm)_baselines.kpm: selinux_hook.c Makefile
	@mkdir -p $(OUT_DIR)
	@test ! -e $@
	$(CC) $(CFLAGS) $(MODE_FLAGS) $(INCLUDE_FLAGS) -c selinux_hook.c -o $@.o
	$(LD) -nostdlib -r $@.o -o $@
	$(if $(filter %_baselines.kpm,$@),$(PYTHON) ../patch_offsets.py baseline $@ --source selinux_hook.c --output $@.json)
.PHONY: all dynamic static
