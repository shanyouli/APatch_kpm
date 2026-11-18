KP_DIR ?= ../KernelPatch
CC := clang
LD := ld.lld
HOST_CC ?= cc
OUT_DIR ?= .
INCLUDES := $(addprefix -I$(KP_DIR)/kernel/,include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include)
CFLAGS := --target=aarch64-none-elf -Wall -Wextra -Werror -Wno-unused-parameter -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -ffixed-x18 -mno-outline-atomics -fno-builtin
HOST_CFLAGS := -Wall -Wextra -Werror

all: check $(OUT_DIR)/fgetpriority_0.2.0.kpm

check:
	@mkdir -p $(OUT_DIR)
	$(HOST_CC) $(HOST_CFLAGS) tests/test_policy.c -o $(OUT_DIR)/test_policy
	$(OUT_DIR)/test_policy
	$(HOST_CC) $(HOST_CFLAGS) tests/test_scope.c -o $(OUT_DIR)/test_scope
	$(OUT_DIR)/test_scope
	$(HOST_CC) $(HOST_CFLAGS) -Itests/stubs tests/test_init.c -o $(OUT_DIR)/test_init
	$(OUT_DIR)/test_init

$(OUT_DIR)/fgetpriority.o: fgetpriority.c fgp_policy.h fgp_scope.h fgp_target.h Makefile
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUT_DIR)/fgetpriority_0.2.0.kpm: $(OUT_DIR)/fgetpriority.o
	@test ! -e $@
	$(LD) -m aarch64elf -r $< -o $@

.PHONY: all check
