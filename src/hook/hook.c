/*
 * Inspired by https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/qemu_persistent_hook/read_into_rdi.c
 */
#include "hook.h"
#include <string.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x) - guest_base)

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base, uint8_t *input_buf, uint32_t input_buf_len) {
  // Make sure we don't overflow the target buffer
  if (input_buf_len > 4096)
    input_buf_len = 4096;

  // Copy the fuzz data to the target's memory
  memcpy(g2h(regs->rdi), input_buf, input_buf_len);

  // Update the length
  regs->rsi = input_buf_len;
}

int afl_persistent_hook_init(void) {
  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;
}
