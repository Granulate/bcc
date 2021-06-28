/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include <cstdio>
#include <ctime>
#include <algorithm>
#include <string>
#include <vector>
#include <limits.h>
#include <sys/time.h>

#include "PyPerfCollapsedPrinter.h"
#include "PyPerfProfiler.h"
#include "PyPerfNativeStackTrace.h"

namespace ebpf {
namespace pyperf {

const static std::string kLostSymbol = "[Lost Symbol]";
const static std::string kTruncatedStack = "[Truncated]";

PyPerfCollapsedPrinter::PyPerfCollapsedPrinter(std::string& output) {
  output_ = output;
}

namespace {
// Copied from linux: tools/perf/util/time-utils.c
int fetch_current_timestamp(char *buf, size_t sz)
{
  struct timeval tv;
  struct tm tm;
  char dt[32];

  if (gettimeofday(&tv, NULL) || !localtime_r(&tv.tv_sec, &tm))
    return -1;

  if (!strftime(dt, sizeof(dt), "%Y%m%d%H%M%S", &tm))
    return -1;

  snprintf(buf, sz, "%s%02u", dt, (unsigned)tv.tv_usec / 10000);

  return 0;
}
}

void PyPerfCollapsedPrinter::open_new() {
  output_file = std::fopen(output_.c_str(), "w");
  if (output_file == NULL) {
    std::fprintf(stderr, "fopen(\"%s\"): %s\n", output_.c_str(), strerror(errno));
    return;
  }

  char timestamp[] = "InvalidTimestamp";
  (void)fetch_current_timestamp(timestamp, sizeof(timestamp));
  std::snprintf(final_path, sizeof(final_path), "%s.%s", output_.c_str(), timestamp);
}

void PyPerfCollapsedPrinter::prepare() {
  if (!output_.empty()) {
    open_new();
  }
  else {
    output_file = stdout;
  }
}

const char *PyPerfCollapsedPrinter::sample_strerror(enum error_code error) {
  switch (error) {
    case ERROR_NONE: return "ERROR_NONE";
    case ERROR_MISSING_PYSTATE: return "ERROR_MISSING_PYSTATE";
    case ERROR_THREAD_STATE_NULL: return "ERROR_THREAD_STATE_NULL";
    case ERROR_INTERPRETER_NULL: return "ERROR_INTERPRETER_NULL";
    case ERROR_TOO_MANY_THREADS: return "ERROR_TOO_MANY_THREADS";
    case ERROR_THREAD_STATE_NOT_FOUND: return "ERROR_THREAD_STATE_NOT_FOUND";
    case ERROR_EMPTY_STACK: return "ERROR_EMPTY_STACK";
    case ERROR_BAD_FSBASE: return "ERROR_BAD_FSBASE";
    case ERROR_INVALID_PTHREADS_IMPL: return "ERROR_INVALID_PTHREADS_IMPL";
    case ERROR_THREAD_STATE_HEAD_NULL: return "ERROR_THREAD_STATE_HEAD_NULL";
    case ERROR_BAD_THREAD_STATE: return "ERROR_BAD_THREAD_STATE";
    case ERROR_CALL_FAILED: return "ERROR_CALL_FAILED";
    default: return "ERROR_UNKNOWN_CODE";
  }
}

void PyPerfCollapsedPrinter::processSamples(
    const std::vector<PyPerfSample>& samples, PyPerfProfiler* util) {
  unsigned int errors = 0;
  unsigned int symbolErrors = 0;
  unsigned int lostSymbols = 0;
  unsigned int truncatedStack = 0;
  unsigned int kernelStackErrors = 0;
  unsigned int nativeStackErrors = 0;

  auto symbols = util->getSymbolMapping();
  auto kernelStacks = util->getKernelStackTraces();
  for (auto& sample : samples) {
    int frames = 0;
    std::fprintf(output_file, "%s-%d/%d", sample.comm.c_str(), sample.pid, sample.tid);

    switch (sample.stackStatus) {
    case STACK_STATUS_TRUNCATED:
      std::fprintf(output_file, ";%s_[pe]", kTruncatedStack.c_str());
      truncatedStack++;
      break;
    case STACK_STATUS_ERROR:
      std::fprintf(output_file, ";[Sample Error %s]_[pe]", sample_strerror((enum error_code)sample.errorCode));
      errors++;
      break;
    }

    for (auto it = sample.pyStackIds.crbegin(); it != sample.pyStackIds.crend(); ++it) {
      const auto stackId = *it;
      if (stackId < 0) {
        if (stackId == FRAME_CODE_IS_NULL) {
          std::fprintf(output_file, ";(missing)_[pe]");
        }
        else {
          std::fprintf(output_file, ";[Error (errnos) %d]_[pe]", -stackId);
          symbolErrors++;
        }
      }
      else {
        auto symbIt = symbols.find(stackId);
        if (symbIt != symbols.end()) {
          std::fprintf(output_file, ";%s_[p]", symbIt->second.c_str());
          frames++;
        } else {
          std::fprintf(output_file, ";%s_[pe]", kLostSymbol.c_str());
          lostSymbols++;
        }
      }
    }

    nativeStackErrors += static_cast<int>(sample.nativeStack.error_occured());
    auto native_symbols = sample.nativeStack.get_stack_symbol();
    for (auto it = native_symbols.crbegin(); it != native_symbols.crend(); ++it) {
      auto sym = *it;
      std::fprintf(output_file, ";%s_[pn]", sym.c_str());
    }

    if (sample.kernelStackId > 0) {
      auto symbols = kernelStacks.get_stack_symbol(sample.kernelStackId, -1);
      for (auto it = symbols.crbegin(); it != symbols.crend(); ++it) {
        auto sym = *it;
        std::fprintf(output_file, ";%s_[k]", sym.c_str());
      }
    }
    // ignore EFAULT which means there was no kernel stack at that point
    else if (sample.kernelStackId != -EFAULT) {
      kernelStackErrors++;
    }
    std::fprintf(output_file, " %d\n", 1);
  }
  std::fflush(output_file);

  std::fprintf(stderr, "%d samples collected\n", util->getTotalSamples());
  std::fprintf(stderr, "%d samples lost\n", util->getLostSamples());
  std::fprintf(stderr, "%d samples with truncated stack\n", truncatedStack);
  std::fprintf(stderr, "%d Python symbol errors\n", symbolErrors);
  std::fprintf(stderr, "%d times Python symbol lost\n", lostSymbols);
  std::fprintf(stderr, "%d kernel stack errors\n", kernelStackErrors);
  std::fprintf(stderr, "%d native stack errors\n", nativeStackErrors);
  std::fprintf(stderr, "%d errors\n", errors);

  if (!output_.empty()) {
    std::fclose(output_file);
    if (rename(output_.c_str(), final_path) == -1) {
      std::fprintf(stderr, "rename(\"%s\", \"%s\"): %s\n", output_.c_str(), final_path, strerror(errno));
    }
    else {
      std::fprintf(stderr, "Wrote %s\n", final_path);
    }
  }
}

}  // namespace pyperf
}  // namespace ebpf
