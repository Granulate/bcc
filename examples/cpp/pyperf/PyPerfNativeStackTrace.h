/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */
#pragma once

#include <libunwind-ptrace.h>

#include <string>
#include <vector>
#include <map>

namespace ebpf {
namespace pyperf {

typedef struct {
  unw_cursor_t cursor;
  unw_addr_space_t as;
  void *upt;
  time_t timestamp;
  std::vector<std::string> proc_names;
  bool unwinded = false;
} UnwindCacheEntry;

typedef std::map<uint32_t, UnwindCacheEntry> UnwindCache;

class NativeStackTrace {
 public:
  explicit NativeStackTrace(uint32_t pid, const uint8_t *raw_stack,
                            size_t stack_len, uintptr_t ip, uintptr_t sp);

  static void Prune_dead_pid(uint32_t dead_pid);
  std::vector<std::string> get_stack_symbol() const;
  bool error_occured() const;
 private:
  std::vector<std::string> symbols;
  bool error_occurred;
  static UnwindCache cache;

  static const uint8_t *stack;
  static size_t stack_len;
  static uintptr_t ip;
  static uintptr_t sp;
  static time_t now;
  static int dbg_counter;
  static float dbg_maxSize;

  static const uint16_t CacheMaxSizeMB;
  static const uint16_t CacheMaxTTL;

  static uint32_t cache_size();
  static uint32_t cache_single_entry_size();
  static float cache_size_KB();

  static int access_reg(unw_addr_space_t as, unw_regnum_t regnum,
                        unw_word_t *valp, int write, void *arg);

  static int access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *valp,
                        int write, void *arg);

  static void cleanup(void *upt, unw_addr_space_t as);

  bool is_cached(const uint32_t &key);
  void cache_put(const uint32_t &key, const unw_cursor_t cursor,
                 const unw_addr_space_t as, void *upt);
  static UnwindCacheEntry cache_get(const uint32_t &key);
  static bool cache_delete_key(const uint32_t &key);
  static void cache_eviction();
};

}  // namespace pyperf
}  // namespace ebpf
