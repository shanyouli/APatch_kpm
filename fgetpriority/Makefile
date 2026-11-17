KP_DIR ?= ../KernelPatch
CC := clang
LD := ld.lld
OUT_DIR ?= .
INCLUDES := $(addprefix -I$(KP_DIR)/kernel/,include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include)
CFLAGS := --target=aarch64-none-elf -Wall -Wextra -Werror -Wno-unused-parameter -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -ffixed-x18 -mno-outline-atomics -fno-builtin

all: $(OUT_DIR)/fgetpriority_0.1.0_preflight.kpm

$(OUT_DIR)/fgetpriority.o: fgetpriority.c fgp_policy.h fgp_target.h Makefile
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUT_DIR)/fgetpriority_0.1.0_preflight.kpm: $(OUT_DIR)/fgetpriority.o
	@test ! -e $@
	$(LD) -m aarch64elf -r $< -o $@

.PHONY: all
