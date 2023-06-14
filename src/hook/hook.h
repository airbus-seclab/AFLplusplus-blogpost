#ifndef hook_h__
#define hook_h__
#include "qemu_mode/qemuafl/qemuafl/api.h"

extern void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base, uint8_t *input_buf, uint32_t input_buf_len);
extern int afl_persistent_hook_init(void);

#endif  // hook_h__
