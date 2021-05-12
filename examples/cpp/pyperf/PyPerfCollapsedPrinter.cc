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

namespace ebpf {
namespace pyperf {

const static std::string kLostSymbol = "[Lost Symbol]";
const static std::string kIncompleteStack = "[Truncated Stack]";
const static std::string kErrorStack = "[Stack Error]";

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

void PyPerfCollapsedPrinter::processSamples(
    const std::vector<PyPerfSample>& samples, PyPerfProfiler* util) {
  unsigned int errors = 0;
  unsigned int lostSymbols = 0;
  unsigned int truncatedStack = 0;
  unsigned int kernelStackErrors = 0;

  auto symbols = util->getSymbolMapping();
  auto kernelStacks = util->getKernelStackTraces();
  for (auto& sample : samples) {
    int frames = 0;
    std::fprintf(output_file, "%s-%d/%d", sample.comm.c_str(), sample.pid, sample.tid);
    switch (sample.stackStatus) {
    case STACK_STATUS_TRUNCATED:
      std::fprintf(output_file, ";%s", kIncompleteStack.c_str());
      truncatedStack++;
      break;
    case STACK_STATUS_ERROR:
      std::fprintf(output_file, ";%s", kErrorStack.c_str());
      errors++;
      break;
    default:
      for (auto it = sample.pyStackIds.crbegin(); it != sample.pyStackIds.crend(); ++it) {
        const auto stackId = *it;
        auto symbIt = symbols.find(stackId);
        if (symbIt != symbols.end()) {
          std::fprintf(output_file, ";%s", symbIt->second.c_str());
          frames++;
        } else {
          std::fprintf(output_file, ";%s", kLostSymbol.c_str());
          lostSymbols++;
        }
      }
      if (sample.kernelStackId > 0) {
        auto stacks = kernelStacks.get_stack_symbol(sample.kernelStackId, -1);
        for (auto it = stacks.crbegin(); it != stacks.crend(); ++it) {
          auto sym = *it;
          std::fprintf(output_file, ";%s_[k]", sym.c_str());
        }
      // ignore EFAULT which means there was no kernel stack at that point
      } else if (sample.kernelStackId != -EFAULT) {
        kernelStackErrors++;
      }
      break;
    }
    if (frames == 0) {
      std::fprintf(output_file, ";error_code_%d", sample.errorCode);
    }
    std::fprintf(output_file, " %d\n", 1);
  }
  std::fflush(output_file);

  std::fprintf(stderr, "%d samples collected\n", util->getTotalSamples());
  std::fprintf(stderr, "%d samples lost\n", util->getLostSamples());
  std::fprintf(stderr, "%d samples with truncated stack\n", truncatedStack);
  std::fprintf(stderr, "%d times Python symbol lost\n", lostSymbols);
  std::fprintf(stderr, "%d kernel stack errors\n", kernelStackErrors);
  std::fprintf(stderr, "%d errors\n", errors);

  if (!output_.empty()) {
    std::fclose(output_file);
    if (rename(output_.c_str(), final_path) == -1) {
      std::fprintf(stderr, "rename(\"%s\", \"%s\"): %s\n", output_.c_str(), final_path, strerror(errno));
    }
  }
}

}  // namespace pyperf
}  // namespace ebpf
