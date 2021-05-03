/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfProfiler.h"

#include <fcntl.h>
#include <dirent.h>
#include <linux/elf.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <regex>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <thread>

#include "PyPerfLoggingHelper.h"
#include "PyPerfVersion.h"
#include "PyPerfProc.h"
#include "bcc_elf.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

namespace ebpf {
namespace pyperf {

using namespace std::chrono_literals;

extern std::string PYPERF_BPF_PROGRAM;

const static int kPerfBufSizePages = 32;

const static std::string kPidCfgTableName("pid_config");
const static std::string kProgsTableName("progs");
const static std::string kSamplePerfBufName("events");

const static std::string kOnEventFuncName("on_event");

const static std::string kPythonStackFuncName("read_python_stack");
const static std::string kPythonStackProgIdxFlag("-DPYTHON_STACK_PROG_IDX=");
const static std::string kGetThreadStateFuncName("get_thread_state");
const static std::string kGetThreadStateProgIdxFlag("-DGET_THREAD_STATE_PROG_IDX=");
const static int kPythonStackProgIdx = 0;
const static int kGetThreadStateProgIdx = 1;

const static std::string kNumCpusFlag("-DNUM_CPUS=");
const static std::string kSymbolsHashSizeFlag("-D__SYMBOLS_SIZE__=");
const static int kSymbolsHashSize = 16384;

namespace {

bool allAddrFound(const PythonSymbols& symbols) {
  return (symbols._PyRuntime || symbols._PyThreadState_Current);
}

int getAddrOfPythonBinaryCallback(const char* name, uint64_t value, uint64_t, void* payload) {
  auto checkAndGetAddr = [&](uintptr_t& destValue, const char* targetName) {
    if (destValue == 0 && std::strcmp(name, targetName) == 0) {
      destValue = value;
    }
  };

  PythonSymbols& symbols = *static_cast<PythonSymbols*>(payload);
  checkAndGetAddr(symbols._PyRuntime, "_PyRuntime");
  checkAndGetAddr(symbols._PyThreadState_Current, "_PyThreadState_Current");
  if (allAddrFound(symbols)) {
    // terminate the search
    return -1;
  }
  return 0;
}

const std::string kPyLibName = "libpython";
const std::string kPyExeName = "python";

/*
Runs for each executable entry in /proc/<pid>/maps
*/
int execMapsCallback(mod_info *mod, int, void* payload) {
  auto helper = static_cast<ExecMapsHelper*>(payload);
  std::string file = mod->name;

  if (!helper->is_musl && file.find("musl") != std::string::npos) {
    helper->is_musl = true;
  }

  /*
  There are two possible cases:
    1. Static Python process that contains all Python symbols.
    2. Dynamic Python process where all the symbols are defined in a libpython*.so.
  We have to know in which file to look for the symbols. For that we have to first
  determine which of these cases applies. Because a "python*" executable is mapped in
  both cases, we have to look for "libpython*" first, which is only mapped in the
  second case. In addition, we must not stop searching for libpython* when we find
  python* because it most likely appears in a later entry.
  */
  if (!helper->found_lib) {
    auto pos = file.rfind("/");
    if (pos != std::string::npos) {
      file = file.substr(pos + 1);
    }

    std::string pymodname;
    if (file.find(kPyLibName) == 0) {
      helper->found_lib = true;
      pymodname = kPyLibName;
    }
    else if (file.find(kPyExeName) == 0) {
      helper->found_exe = true;
      pymodname = kPyExeName;
    }

    if (!pymodname.empty()) {
      // Use the end of the substring as the beginning of the version:
      size_t ver_start = pymodname.size();
      // assume major is "2." or "3." (2 chars)
      // minor can contain more than 1 digit:
      ssize_t ver_end = file.find_first_not_of("0123456789", ver_start + 2);
      if (ver_end == -1) {
        ver_end = file.size();
      }

      // Set all the fields.
      helper->path = mod->name;
      helper->exec_start = mod->start_addr;
      helper->version = file.substr(ver_start, ver_end - ver_start);
      helper->device = makedev(mod->dev_major, mod->dev_minor);
      helper->inode = mod->inode;
    }
  }
  return 0;
}

int findExecVaddrCallback(uint64_t vaddr, uint64_t memsz, uint64_t offset, void *payload) {
  // 1. File should have only one executable segment.
  // 2. Even if it were to have more, LOAD segments are sorted by ascending vaddr,
  //    so we only care about the first.
  auto helper = static_cast<PythonExecutableInfo*>(payload);
  helper->exec_vaddr = vaddr;
  return -1;
}
}  // namespace

void handleSampleCallback(void* cb_cookie, void* raw_data, int data_size) {
  auto profiler = static_cast<PyPerfProfiler*>(cb_cookie);
  profiler->handleSample(raw_data, data_size);
}

void handleLostSamplesCallback(void* cb_cookie, uint64_t lost_cnt) {
  auto profiler = static_cast<PyPerfProfiler*>(cb_cookie);
  profiler->handleLostSamples(lost_cnt);
}

PyPerfProfiler::PyPerfResult PyPerfProfiler::init() {
  std::vector<std::string> cflags;
  cflags.emplace_back(kNumCpusFlag + std::to_string(::sysconf(_SC_NPROCESSORS_ONLN)));
  cflags.emplace_back(kSymbolsHashSizeFlag + std::to_string(kSymbolsHashSize));
  cflags.emplace_back(kPythonStackProgIdxFlag + std::to_string(kPythonStackProgIdx));
  cflags.emplace_back(kGetThreadStateProgIdxFlag + std::to_string(kGetThreadStateProgIdx));

  auto initRes = bpf_.init(PYPERF_BPF_PROGRAM, cflags);
  if (initRes.code() != 0) {
    std::fprintf(stderr, "Failed to compiled PyPerf BPF programs: %s\n",
                 initRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  auto progTable = bpf_.get_prog_table(kProgsTableName);
  if (progTable.capacity() != 2) {
    std::fprintf(stderr, "Programs table %s expected to hold 2 programs, but holds %ld instead.\n",
      kProgsTableName.c_str(), progTable.capacity());
    return PyPerfResult::INIT_FAIL;
  }

  int progFd = -1;

  auto loadRes = bpf_.load_func(kPythonStackFuncName, BPF_PROG_TYPE_PERF_EVENT, progFd);
  if (loadRes.code() != 0) {
    std::fprintf(stderr, "Failed to load BPF program %s: %s\n", kPythonStackFuncName.c_str(), loadRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }
  auto updateRes = progTable.update_value(kPythonStackProgIdx, progFd);
  if (updateRes.code() != 0) {
    std::fprintf(stderr,
                 "Failed to set BPF program %s FD %d to program table: %s\n",
                 kPythonStackFuncName.c_str(), progFd, updateRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  loadRes = bpf_.load_func(kGetThreadStateFuncName, BPF_PROG_TYPE_PERF_EVENT, progFd);
  if (loadRes.code() != 0) {
    std::fprintf(stderr, "Failed to load BPF program %s: %s\n", kGetThreadStateFuncName.c_str(), loadRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  updateRes = progTable.update_value(kGetThreadStateProgIdx, progFd);
  if (updateRes.code() != 0) {
    std::fprintf(stderr,
                 "Failed to set BPF program %s FD %d to program table: %s\n",
                 kGetThreadStateFuncName.c_str(), progFd, updateRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  initCompleted_ = true;
  return PyPerfResult::SUCCESS;
}

/**
Populate the PidData BPF map.
*/
bool PyPerfProfiler::populatePidTable() {
  bool result = false;

  // Populate config for each Python Process
  auto pid_config_map = bpf_.get_hash_table<int, PidData>(kPidCfgTableName);

  logInfo(3, "Populating pid table\n");
  for (const auto pid : pids) {
    PidData pidData;

    auto status = pid_config_map.get_value(pid, pidData);
    if (status.code() == 0) {
      result = true;
      continue;
    }

    if (!tryTargetPid(pid, pidData)) {
      // Not a Python Process
      continue;
    }
    pid_config_map.update_value(pid, pidData);

    result = true;
  }

  return result;
}

void PyPerfProfiler::handleSample(const void* data, int dataSize) {
  const Event* raw = static_cast<const Event*>(data);
  samples_.emplace_back(raw, dataSize);
  totalSamples_++;
}

void PyPerfProfiler::handleLostSamples(int lostCnt) { lostSamples_ += lostCnt; }

void PyPerfProfiler::updateProcesses() {
  auto update_time = std::chrono::steady_clock::time_point{};
  while (inProgress_) {
    if (std::chrono::steady_clock::now() >= update_time) {
      update_time = std::chrono::steady_clock::now() + update_interval;
      pids.clear();
      if (!getRunningPids(pids)) {
        std::fprintf(stderr, "Failed getting running processes\n");
      }
      else if (!populatePidTable()) {
        logInfo(3, "No processes to profile\n");
      }
    }
    std::this_thread::sleep_for(1s);
  }
}

void PyPerfProfiler::on_dump_signal() {
  dump_flag = true;
}

PyPerfProfiler::PyPerfResult PyPerfProfiler::profile(
    int64_t sampleRate,
    int64_t sampleFreq,
    int64_t duration,
    PyPerfSampleProcessor* processor) {
  if (!initCompleted_) {
    std::fprintf(stderr, "PyPerfProfiler::init not invoked or failed\n");
    return PyPerfResult::NO_INIT;
  }

  // Open perf buffer
  auto openRes = bpf_.open_perf_buffer(kSamplePerfBufName, &handleSampleCallback, &handleLostSamplesCallback,
                                       this, kPerfBufSizePages);
  if (openRes.code() != 0) {
    std::fprintf(stderr, "Unable to open Perf Buffer: %s\n", openRes.msg().c_str());
    return PyPerfResult::PERF_BUF_OPEN_FAIL;
  }

  // Attach to CPU cycles
  auto attachRes =
      bpf_.attach_perf_event(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, kOnEventFuncName, sampleRate, sampleFreq);
  if (attachRes.code() != 0) {
    std::fprintf(stderr, "Attach to CPU cycles event failed: %s\n",
                 attachRes.msg().c_str());
    return PyPerfResult::EVENT_ATTACH_FAIL;
  }
  logInfo(2, "Attached to profiling event\n");

  // Get Perf Buffer and poll in a loop for a given duration
  auto perfBuffer = bpf_.get_perf_buffer(kSamplePerfBufName);
  if (!perfBuffer) {
    std::fprintf(stderr, "Failed to get Perf Buffer: %s\n",
                 kSamplePerfBufName.c_str());
    return PyPerfResult::PERF_BUF_OPEN_FAIL;
  }

  processor->prepare();

  inProgress_ = true;
  std::thread processPollingThread{&PyPerfProfiler::updateProcesses, this};

  logInfo(2, "Started polling Perf Buffer\n");
  auto start = std::chrono::steady_clock::now();
  auto end = start + std::chrono::seconds(duration);
  while (duration == 0 || std::chrono::steady_clock::now() < end) {
    perfBuffer->poll(50 /* 50ms timeout */);
    if (dump_flag) {
      dump_flag = false;
      processor->processSamples(samples_, this);
      samples_.clear();
      totalSamples_ = 0;
      processor->prepare();
    }
  }
  inProgress_ = false;
  processPollingThread.join();

  logInfo(2, "Profiling duration finished\n");

  // Detach the event
  auto detachRes = bpf_.detach_perf_event(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
  assert(detachRes.ok());
  logInfo(2, "Detached from profiling event\n");

  // Drain remaining samples
  logInfo(2, "Draining remaining samples\n");
  while (perfBuffer->poll(0) > 0) {
  }
  logInfo(2, "Finished draining remaining samples\n");

  processor->processSamples(samples_, this);

  return PyPerfResult::SUCCESS;
}

std::unordered_map<int32_t, std::string> PyPerfProfiler::getSymbolMapping() {
  // BPF program records a mapping from symbols to their ids.
  // Swap them here to map the ids back to the symbols they represent
  auto symbolTable = bpf_.get_hash_table<Symbol, int32_t>("symbols");
  std::unordered_map<int32_t, std::string> symbols;
  for (auto& x : symbolTable.get_table_offline()) {
    auto symbolName = getSymbolName(x.first);
    logInfo(2, "Symbol ID %d is %s\n", x.second, symbolName.c_str());
    symbols.emplace(x.second, std::move(symbolName));
  }
  logInfo(1, "Total %d unique Python symbols\n", symbols.size());
  return symbols;
}

std::string PyPerfProfiler::getSymbolName(Symbol& sym) const {
  std::string nameStr = std::string(sym.name).substr(0, FUNCTION_NAME_LEN);
  std::string classStr = std::string(sym.classname).substr(0, CLASS_NAME_LEN);
  if (classStr.size() > 0) {
    nameStr = classStr + "." + nameStr;
  }

  std::string file = std::string(sym.file).substr(0, FILE_NAME_LEN);
  if (file.empty()) {
    return nameStr;
  }

  std::string module = file;
  /*
  Derive the module name from the file path. This covers the most common cases: built-ins, installed packages, and zip imports.
  Alternatively we could traverse the path looking for the package root (highest __init__.py file). Though it still wouldn't cover
  arbitrary importers.

  Strip the following in order:
    1. For zip packages: path to the zip file.
    2. Installation prefix: /usr, /usr/local, /opt, /opt/python*
    3. Path to the packages root: /lib(32/64)/python* for built-in package, followed by site/dist-packages for installed packages.
    4. Leading slash.
    5. .py file extension.
  Then replace all slashes with periods.
  */
  module = std::regex_replace(module, std::regex{R"(^.*?\.zip/)"}, "");
  module = std::regex_replace(module, std::regex{R"(^(/usr(/local)?|/opt(/python[23](\.[0-9]+)?)?))"}, "");
  module = std::regex_replace(module, std::regex{R"(^/lib(32|64)?/python[23](\.[0-9]+)?(/(site|dist)\-packages)?)"}, "");
  module = std::regex_replace(module, std::regex{R"(^/)"}, "");
  module = std::regex_replace(module, std::regex{R"(\.(py|pyc|pyo)$)"}, "");
  std::replace(module.begin(), module.end(), '/', '.');
  return module + "." + nameStr + " (" + file + ")";
}

void get_exec_vaddr(std::string& path, PythonExecutableInfo& info) {
  bcc_elf_foreach_load_section(path.c_str(), &findExecVaddrCallback, &info);
}

bool get_python_symbols(std::string& path, PythonSymbols& symbols) {
  struct bcc_symbol_option option{};
  option.use_symbol_type = (1 << STT_OBJECT) | (1 << STT_FUNC);
  int result = bcc_elf_foreach_sym(path.c_str(), &getAddrOfPythonBinaryCallback, &option, &symbols);
  if (result < 0) {
    std::fprintf(stderr, "Failed to iterate over ELF symbols: %s\n", path.c_str());
    return false;
  }

  if (!allAddrFound(symbols)) {
    std::fprintf(stderr, "Python symbols not found: %s\n", path.c_str());
    return false;
  }

  return true;
}

bool PyPerfProfiler::handle_new_python_module(
  std::string& inode_path,
  ExecMapsHelper& helper,
  PythonExecutableInfo& this_python) {

  this_python = {};  // zero
  this_python.device = helper.device;
  this_python.inode = helper.inode;
  this_python.pthreads_impl = helper.is_musl ? PTI_MUSL : PTI_GLIBC;

  get_exec_vaddr(inode_path, this_python);

  if (!get_python_symbols(inode_path, this_python.symbols)) {
    return false;
  }

  int python_fd = open(inode_path.c_str(), O_RDONLY);
  if (python_fd < 0) {
    logInfo(1, "Python inode gone: %s\n", inode_path.c_str());
    return false;
  }

  version version{};
  if (!get_python_version(python_fd, helper.version, version)) {
    std::fprintf(stderr, "Failed to detect Python version\n");
    close(python_fd);
    return false;
  }
  else {
    logInfo(1, "Detected Python version: %u.%u.%u\n", version.major, version.minor, version.patch);
  }

  this_python.offsets = get_offsets(version);
  pythons_.push_back(this_python);
  close(python_fd);
  return true;
}

bool PyPerfProfiler::tryTargetPid(int pid, PidData& data) {
  if (!filter_kernel_thread(pid)) {
    return false;
  }

  // Look for Python symbols in the memory of the process
  ExecMapsHelper helper{};
  bcc_procutils_each_module(pid, &execMapsCallback, &helper);
  if (!helper.found_exe && !helper.found_lib) {
    logInfo(3, "[%6d] Process does not contain Python library\n", pid);
    return false;
  }

  bool is_existing_python = false;
  PythonExecutableInfo this_python;
  for (auto item : pythons_) {
    if (item.device == helper.device &&
        item.inode == helper.inode) {
      this_python = item;
      is_existing_python = true;
      break;
    }
  }

  if (!is_existing_python) {
    std::string inode_path;
    if (!get_pid_path(pid, helper.path, inode_path)) {
      fprintf(stderr, "[%6d] Failed to get PID path: %s\n", pid, helper.path.c_str());
      return false;
    }

    if (!handle_new_python_module(inode_path, helper, this_python)) {
      fprintf(stderr, "[%6d] Setup new python failed\n", pid);
      return false;
    }
  }

  uint64_t base = helper.exec_start - this_python.exec_vaddr;
  logInfo(1, "[%6d] %s @ 0x%016lx\n", pid, helper.path.c_str(), base);

  std::memset(&data, 0, sizeof(data));
  data.pthreads_impl = this_python.pthreads_impl;

  // For the arbitrary constant buffer let's just use the start of the executable segment, which is
  // definitely constant.
  data.globals.constant_buffer = base + this_python.exec_vaddr;
  data.offsets = this_python.offsets;

  // one of _PyRuntime or _PyThreadState_Current is set, depending on Python version
  if (this_python.symbols._PyRuntime != 0) {
    data.globals._PyRuntime = base + this_python.symbols._PyRuntime;
    logInfo(2, "[%6d] _PyRuntime @ 0x%016lx\n", pid, data.globals._PyRuntime);
  }
  else {
    assert(this_python.symbols._PyThreadState_Current != 0);
    data.globals._PyThreadState_Current = base + this_python.symbols._PyThreadState_Current;
    logInfo(2, "[%6d] _PyThreadState_Current @ 0x%016lx\n", pid, data.globals._PyThreadState_Current);
  }
  return true;
}

}  // namespace pyperf
}  // namespace ebpf
