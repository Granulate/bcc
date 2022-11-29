/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfNativeStackTrace.h"

#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <cxxabi.h>
#include <limits.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>

#include "PyPerfLoggingHelper.h"
#include "bcc_syms.h"
#include "syms.h"

namespace ebpf {
namespace pyperf {

using std::unique_ptr;

// Ideally it was preferable to save this as the context in libunwind accessors, but it's already used by UPT
const uint8_t *NativeStackTrace::stack = NULL;
size_t NativeStackTrace::stack_len = 0;
uintptr_t NativeStackTrace::sp = 0;
uintptr_t NativeStackTrace::ip = 0;
ProcSymbolsCache NativeStackTrace::procSymbolsCache;
bool NativeStackTrace::insert_dso_name = false;
const static double ProcSymbolsCacheTTL_S = 60;

// external public symbol max size according to recommendation in c++ standard annex B
const static int SymbolMaxSize = 1024;

static double steady_time_since_epoch() {
  return std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

NativeStackTrace::NativeStackTrace(uint32_t pid, const unsigned char *raw_stack,
                                   size_t stack_len, uintptr_t ip, uintptr_t sp) : error_occurred(false) {
  NativeStackTrace::stack = raw_stack;
  NativeStackTrace::stack_len = stack_len;
  NativeStackTrace::ip = ip;
  NativeStackTrace::sp = sp;

  if (stack_len == 0) {
    return;
  }

  unw_accessors_t my_accessors = _UPT_accessors;
  my_accessors.access_mem = NativeStackTrace::access_mem;
  my_accessors.access_reg = NativeStackTrace::access_reg;
  ProcSyms* procSymbols = nullptr;
  // reserve memory for platform-defined path limit AND the symbol
  const size_t buf_size = SymbolMaxSize + PATH_MAX + sizeof("() ");
  char buf[buf_size];

  // The UPT implementation of these functions uses ptrace. We want to make sure they aren't getting called
  my_accessors.access_fpreg = NULL;
  my_accessors.resume = NULL;

  int res;
  unw_addr_space_t as = unw_create_addr_space(&my_accessors, 0);
  void *upt = _UPT_create(pid);
  if (!upt) {
    this->symbols.push_back(std::string("[Error _UPT_create (system OOM)]"));
    this->error_occurred = true;
    goto out;
  }

  unw_cursor_t cursor;
  // TODO: It's possible to make libunwind use cache using unw_set_caching_policy, which might lead to significent
  //       performance improvement. We just need to make sure it's not dangerous. For now the overhead is good enough.
  res = unw_init_remote(&cursor, as, upt);
  if (res) {
    std::ostringstream error;
    error << "[Error unw_init_remote (" << unw_strerror(res) << ")]";
    this->symbols.push_back(error.str());
    this->error_occurred = true;
    goto out;
  }

  if (NativeStackTrace::insert_dso_name) {
    procSymbols = get_proc_symbols(pid);
  }

  do {
    unw_word_t offset;
    unw_word_t ip;
    struct bcc_symbol resolved_symbol;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    if (procSymbols && procSymbols->resolve_addr(ip, &resolved_symbol, true)) {
        snprintf(buf, buf_size, "%s (%s)", resolved_symbol.demangle_name, resolved_symbol.module);
        this->symbols.push_back(std::string(buf));
    // TODO: This function is very heavy. We should try to do some caching here, maybe in the
    //       underlying UPT function.
    } else if (!(res = unw_get_proc_name(&cursor, buf, sizeof(buf), &offset))) {
        int status = 0;
        char* demangled = nullptr;
        demangled = abi::__cxa_demangle(buf, nullptr, nullptr, &status);
        if (!status) {
          this->symbols.push_back(std::string(demangled));
        } else {
          this->symbols.push_back(std::string(buf));
        }
        free(demangled);
    } else {
      unw_word_t sp;
      unw_get_reg(&cursor, UNW_REG_SP, &sp);
      logInfo(2,
              "IP=0x%lx -- error: unable to obtain symbol name for this frame - %s "
              "(frame SP=0x%lx)\n",
              ip, unw_strerror(res), sp);
      this->symbols.push_back(std::string("(missing)"));
      this->error_occurred = true;
      break;
    }

    // Unwind only until we get to the function from which the current Python function is executed.
    // On Python3 the main loop function is called "_PyEval_EvalFrameDefault", and on Python2 it's
    // "PyEval_EvalFrameEx".
    if (symbols.back().compare(0, strlen("_PyEval_EvalFrameDefault"), "_PyEval_EvalFrameDefault") == 0 ||
        symbols.back().compare(0, strlen("PyEval_EvalFrameEx"), "PyEval_EvalFrameEx") == 0)
    {
      break;
    }
  } while (unw_step(&cursor) > 0);

out:
  if (upt) {
    _UPT_destroy(upt);
  }
  if (as) {
    unw_destroy_addr_space(as);
  }
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
    logInfo(3, "Libunwind attempts to %s regnum %d\n", write ? "write" : "read", regnum);
    return -UNW_EBADREG;
  }
}

int NativeStackTrace::access_mem(unw_addr_space_t as, unw_word_t addr,
                                 unw_word_t *valp, int write, void *arg) {
  if (write) {
    logInfo(3, "Libunwind unexpected mem write attempt\n");
    return -UNW_EINVAL;
  }

  // Subtract 128 for x86-ABI red zone
  const uintptr_t top_of_stack = NativeStackTrace::sp - 128;
  const uintptr_t stack_start = top_of_stack & ~(getpagesize() - 1);
  const uintptr_t stack_end = stack_start + NativeStackTrace::stack_len;

  if (addr >= top_of_stack && addr < stack_end) {
    memcpy(valp, &stack[addr - stack_start], sizeof(*valp));
    return 0;
  } else if ((addr >= stack_end && addr < stack_end + getpagesize() * 32) ||
             (addr >= stack_start - getpagesize() * 32 && addr < top_of_stack)) {
    // Memory accesses around the pages we copied are assumed to be accesses to the
    // stack that we shouldn't allow
    logInfo(2, "Libunwind attempt to access stack at not-copied address 0x%lx (SP=0x%lx)\n", addr,
            NativeStackTrace::sp);
    return -UNW_EINVAL;
  }

  // Naive cache for this kind of requests.
  // The improvement here is pretty significant - libunwind performs consecutive calls with the same
  // address, so it has around 70-80% hit rate
  // TODO: Maybe we can improve it further by cacheing the entire page
  static unw_word_t last_valp = 0;
  static unw_word_t last_addr = 0;

  if (addr == last_addr) {
    *valp = last_valp;
    return 0;
  }

  struct iovec local = {valp, sizeof(*valp)};
  struct iovec remote = {(void *)addr, sizeof(*valp)};

  if (process_vm_readv(*(pid_t *)arg, &local, 1, &remote, 1, 0) ==
      sizeof(*valp)) {
    last_addr = addr;
    last_valp = *valp;
    return 0;
  }

  logInfo(2, "Write to 0x%lx using process_vm_readv failed with %d (%s)\n", addr, errno, strerror(errno));
  return -UNW_EINVAL;
}

std::vector<std::string> NativeStackTrace::get_stack_symbol() const {
  return symbols;
}

bool NativeStackTrace::error_occured() const {
  return error_occurred;
}

void NativeStackTrace::prune_dead_pid(uint32_t dead_pid) {
  auto it = procSymbolsCache.find(dead_pid);
  if (it != procSymbolsCache.end()) {
    procSymbolsCache.erase(it);
  }
}

void NativeStackTrace::enable_dso_reporting() {
  NativeStackTrace::insert_dso_name = true;
}

ProcSyms* NativeStackTrace::get_proc_symbols(uint32_t pid) {
  struct bcc_symbol_option symbol_options = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
    .use_symbol_type = BCC_SYM_ALL_TYPES
  };
  double timestamp_s = steady_time_since_epoch();
  if (!procSymbolsCache.count(pid)) {
    procSymbolsCache[pid] = ProcSymbolsCacheEntry{timestamp_s, unique_ptr<ProcSyms>(new ProcSyms(pid, &symbol_options))};
  } else {
    if (timestamp_s - procSymbolsCache[pid].timestamp_s > ProcSymbolsCacheTTL_S) {
      procSymbolsCache[pid].proc_syms->refresh();
      procSymbolsCache[pid].timestamp_s = timestamp_s;
    }
  }
  return procSymbolsCache[pid].proc_syms.get();
}

}  // namespace pyperf
}  // namespace ebpf
