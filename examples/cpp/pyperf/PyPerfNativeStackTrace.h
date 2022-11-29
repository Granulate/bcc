/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */
#pragma once

#include <libunwind-ptrace.h>

#include <map>
#include <memory>
#include <string>
#include <vector>
#include "syms.h"

namespace ebpf {
namespace pyperf {

typedef struct {
    double timestamp_s;
    std::unique_ptr<ProcSyms> proc_syms;
} ProcSymbolsCacheEntry;

typedef std::map<uint32_t, ProcSymbolsCacheEntry> ProcSymbolsCache;

class NativeStackTrace {
 public:
  explicit NativeStackTrace(uint32_t pid, const uint8_t *raw_stack,
                            size_t stack_len, uintptr_t ip, uintptr_t sp);

  std::vector<std::string> get_stack_symbol() const;
  bool error_occured() const;
  static void prune_dead_pid(uint32_t dead_pid);
  static void enable_dso_reporting();
  static bool insert_dso_name;

 private:
  std::vector<std::string> symbols;
  bool error_occurred;

  static const uint8_t *stack;
  static size_t stack_len;
  static uintptr_t ip;
  static uintptr_t sp;
  static ProcSymbolsCache procSymbolsCache;

  static int access_reg(unw_addr_space_t as, unw_regnum_t regnum,
                        unw_word_t *valp, int write, void *arg);

  static int access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *valp,
                        int write, void *arg);
  static ProcSyms* get_proc_symbols(uint32_t pid);
};

}  // namespace pyperf
}  // namespace ebpf
