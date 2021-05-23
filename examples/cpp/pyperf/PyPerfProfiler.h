/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#pragma once

#include <atomic>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>

#include <linux/perf_event.h>
#include <sys/types.h>

#include "BPF.h"
#include "PyPerfSampleProcessor.h"
#include "PyPerfType.h"
#include "PyPerfVersion.h"

namespace ebpf {
namespace pyperf {

struct PythonSymbols {
  uint64_t _PyRuntime;
  uint64_t _PyThreadState_Current;
};

struct PythonExecutableInfo {
  dev_t device;      //< st_dev
  ino_t inode;       //< st_ino
  uint64_t exec_vaddr;    //< p_vaddr of first executable LOAD segment
  PythonSymbols symbols;
  struct struct_offsets offsets;
  enum pthreads_impl pthreads_impl;
};

typedef struct {
  // This field serves a dual purpose:
  // First it is set to a substring of the path to search. When a path with the given
  // substring is found, it is replaced with the full path that contains the substring.
  std::string path;
  std::string version;  //< version from filename (MAJOR.MINOR)
  bool found_exe;       //< found python* module in maps
  bool found_lib;       //< found libpython* module in maps
  uint64_t exec_start;  //< virtual address of mapped executable segment
  dev_t device;
  ino_t inode;
  bool is_musl;         //< does this Python use musl libc?
} ExecMapsHelper;

class PyPerfProfiler {
 public:
  enum class PyPerfResult : int {
    SUCCESS = 0,
    INIT_FAIL,
    LIST_PROCESSES_FAIL,
    PERF_BUF_OPEN_FAIL,
    NO_INIT,
    EVENT_ATTACH_FAIL
  };

  // init must be invoked exactly once before invoking profile
  PyPerfResult init(unsigned int symbolsMapSize, unsigned int eventsBufferPages, unsigned int kernelStacksMapSize);

  PyPerfResult profile(int64_t sampleRate, int64_t sampleFreq, int64_t duration,
                       PyPerfSampleProcessor* processor);

  std::unordered_map<int32_t, std::string> getSymbolMapping();
  BPFStackTable getKernelStackTraces() { return bpf_.get_stack_table("kernel_stacks"); }

  uint32_t getTotalSamples() const { return totalSamples_; }

  uint32_t getLostSamples() const { return lostSamples_; }

  void on_dump_signal();

  std::vector<int> pids;
  std::chrono::seconds update_interval;

 private:
  int eventsBufferPages_;
  uint32_t totalSamples_ = 0, lostSamples_ = 0;

  ebpf::BPF bpf_{0, nullptr, false, "", true};
  std::vector<PythonExecutableInfo> pythons_;
  std::vector<PyPerfSample> samples_;
  std::atomic_bool inProgress_{false};

  bool initCompleted_{false};
  bool dump_flag{false};

  void handleSample(const void* data, int dataSize);
  void handleLostSamples(int lostCnt);
  friend void handleLostSamplesCallback(void*, uint64_t);
  friend void handleSampleCallback(void*, void*, int);

  std::string getSymbolName(Symbol& sym) const;

  bool populatePidTable();
  bool tryTargetPid(int pid, PidData& data);
  void updateProcesses();
  bool handle_new_python_module(std::string&, ExecMapsHelper&, PythonExecutableInfo&);
  bool attach_new_interp_uprobe(
    std::string& path,
    int python_fd,
    unsigned long ip,
    std::string sym_name,
    PythonExecutableInfo& info);
};

extern struct_offsets& get_offsets(version& version);

}  // namespace pyperf
}  // namespace ebpf
