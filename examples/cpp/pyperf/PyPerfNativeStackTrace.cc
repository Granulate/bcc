/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfNativeStackTrace.h"

#include <sys/uio.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <sstream>

#include "PyPerfLoggingHelper.h"

namespace ebpf {
namespace pyperf {

const uint8_t *NativeStackTrace::stack = NULL;
size_t NativeStackTrace::stack_len = 0;
uint64_t NativeStackTrace::sp = 0;
uint64_t NativeStackTrace::ip = 0;

NativeStackTrace::NativeStackTrace(uint32_t pid, const unsigned char *raw_stack,
                                   size_t stack_len, uint64_t ip, uint64_t sp) : error_occurred(false) {
  NativeStackTrace::stack = raw_stack;
  NativeStackTrace::stack_len = stack_len;
  NativeStackTrace::ip = ip;
  NativeStackTrace::sp = sp;

  unw_accessors_t my_accessors = _UPT_accessors;
  my_accessors.access_mem = NativeStackTrace::access_mem;
  my_accessors.access_reg = NativeStackTrace::access_reg;

  unw_addr_space_t as = unw_create_addr_space(&my_accessors, 0);
  void *upt = _UPT_create(pid);
  if (!upt) {
    this->symbols.push_back(std::string("[Error _UPT_create (system OOM)]"));
    this->error_occurred = true;
    return;
  }

  unw_cursor_t cursor;
  int res = unw_init_remote(&cursor, as, upt);
  if (res) {
    std::ostringstream error;
    error << "[Error unw_init_remote (" << unw_strerror(res) << ")]";
    this->symbols.push_back(error.str());
    this->error_occurred = true;
    goto out;
  }

  do {
    unw_word_t offset;
    char sym[256];

    if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
      this->symbols.push_back(std::string(sym));
    } else {
      unw_word_t ip;
      unw_get_reg(&cursor, UNW_REG_IP, &ip);
      logInfo(2,
              "0x%lx -- error: unable to obtain symbol name for this frame "
              "(SP=0x%lx)\n",
              ip, NativeStackTrace::sp);
      this->symbols.push_back(std::string("(missing)"));
      this->error_occurred = true;
      break;
    }

    if (memcmp(sym, "_PyEval_EvalFrameDefault",
                sizeof("_PyEval_EvalFrameDefault")) == 0 ||
        memcmp(sym, "PyEval_EvalFrameEx", sizeof("PyEval_EvalFrameEx")) == 0)
        {
      break;
    }
  } while (unw_step(&cursor) > 0);

out:
  _UPT_destroy(upt);
}

int NativeStackTrace::access_reg(unw_addr_space_t as, unw_regnum_t regnum,
                                 unw_word_t *valp, int write, void *arg) {
  if (regnum == UNW_REG_SP) {
    if (write) {
      logInfo(2, "Libunwind attempts to write to SP\n");
      return -UNW_EINVAL;
    }

    *valp = NativeStackTrace::sp;
    return 0;
  }
  else if (regnum == UNW_REG_IP) {
    if (write) {
      logInfo(2, "Libunwind attempts to write to IP\n");
      return -UNW_EINVAL;
    }

    *valp = NativeStackTrace::ip;
    return 0;
  }
  else {
    logInfo(2, "Libunwind attempts to %s regnum %d\n", write ? "write" : "read", regnum);
    return -UNW_EBADREG;
  }
}

int NativeStackTrace::access_mem(unw_addr_space_t as, unw_word_t addr,
                                 unw_word_t *valp, int write, void *arg) {
  if (write) {
    logInfo(2, "Libunwind mem write attempt\n");
    return -UNW_EINVAL;
  }

  const unw_word_t stack_start = NativeStackTrace::sp & ~(getpagesize() - 1);
  const unw_word_t stack_end = stack_start + NativeStackTrace::stack_len;

  if (addr >= NativeStackTrace::sp && addr < stack_end) {
    memcpy(valp, &stack[addr - stack_start], sizeof(*valp));
    return 0;
  } else if ((addr >= stack_end && addr < stack_end + getpagesize() * 2) ||
             (addr >= stack_start - getpagesize() && addr < NativeStackTrace::sp)) {
    // Memory accesses around the pages we copied are assumed to be accesses to the
    // stack that we shouldn't allow
    logInfo(2, "Libunwind failed attempt to access stack at 0x%lx (SP=0x%lx)\n", addr,
            NativeStackTrace::sp);
    return -UNW_EINVAL;
  }

  struct iovec local = {valp, sizeof(*valp)};
  struct iovec remote = {(void *)addr, sizeof(*valp)};

  if (process_vm_readv(*(pid_t *)arg, &local, 1, &remote, 1, 0) ==
      sizeof(*valp)) {
    return 0;
  }

  logInfo(2, "process_vm_readv to %p failed\n", addr);
  return -UNW_EINVAL;
}

std::vector<std::string> NativeStackTrace::get_stack_symbol() const {
  return symbols;
}

bool NativeStackTrace::error_occured() const {
  return error_occurred;
}

}  // namespace pyperf
}  // namespace ebpf
