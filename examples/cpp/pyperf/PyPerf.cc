/*
 * PyPerf Profile Python Processes with Python stack-trace.
 *        For Linux, uses BCC, eBPF. Embedded C.
 *
 * Example of using BPF to profile Python Processes with Python stack-trace.
 *
 * USAGE: PyPerf [-d|--duration DURATION_MS] [-c|--sample-rate SAMPLE_RATE]
 *               [-v|--verbosity LOG_VERBOSITY]
 *
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include <cinttypes>
#include <cstdlib>
#include <string>
#include <vector>
#include <chrono>
#include <csignal>

#include "PyPerfCollapsedPrinter.h"
#include "PyPerfLoggingHelper.h"
#include "PyPerfProfiler.h"

namespace {

ebpf::pyperf::PyPerfProfiler *g_profiler;

void on_dump_signal(int sig) {
  g_profiler->on_dump_signal();
}

}

int main(int argc, char** argv) {
  // Argument parsing helpers
  int pos = 1;

  auto parseStrArg = [&](std::vector<std::string> argNames, std::string& target) {
    std::string arg(argv[pos]);
    for (const auto& name : argNames) {
      if (arg == name) {
        if (pos == argc) {
          std::fprintf(stderr, "Expect value after %s\n", arg.c_str());
          std::exit(1);
        }
        pos++;
        target = argv[pos];
        return true;
      }
    }
    return false;
  };

  auto parseIntArg = [&](std::vector<std::string> argNames, uint64_t& target) {
    std::string arg(argv[pos]);
    for (const auto& name : argNames) {
      if (arg == name) {
        if (pos == argc) {
          std::fprintf(stderr, "Expect value after %s\n", arg.c_str());
          std::exit(1);
        }
        pos++;
        std::string value(argv[pos]);
        try {
          target = std::stoi(value);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "Expect integer value after %s, got %s: %s\n",
                       arg.c_str(), value.c_str(), e.what());
          std::exit(1);
        }
        return true;
      }
    }
    return false;
  };

  auto parseIntListArg = [&](std::vector<std::string> argNames, std::vector<uint64_t>& target) {
    uint64_t value;
    if (parseIntArg(argNames, value)) {
      target.push_back(value);
      return true;
    }
    return false;
  };

  // Default argument values
  std::vector<uint64_t> pids;
  uint64_t updateIntervalSecs = 10;
  uint64_t symbolsMapSize = 16384;
  uint64_t sampleRate = 0;
  uint64_t sampleFreq = 0;
  uint64_t duration = 0;
  uint64_t verbosityLevel = 0;
  std::string output = "";

  while (true) {
    if (pos >= argc) {
      break;
    }
    bool found = false;
    found = found || parseIntListArg({"-p", "--pid"}, pids);
    found = found || parseIntArg({"-c", "--sample-rate"}, sampleRate);
    found = found || parseIntArg({"-F", "--frequency"}, sampleFreq);
    found = found || parseIntArg({"-d", "--duration"}, duration);
    found = found || parseIntArg({"--update-interval"}, updateIntervalSecs);
    found = found || parseIntArg({"--symbols-map-size"}, symbolsMapSize);
    found = found || parseIntArg({"-v", "--verbose"}, verbosityLevel);
    found = found || parseStrArg({"-o", "--output"}, output);
    if (!found) {
      std::fprintf(stderr, "Unexpected argument: %s\n", argv[pos]);
      std::exit(1);
    }
    pos++;
  }

  ebpf::pyperf::setVerbosity(verbosityLevel);

  if (sampleFreq == 0 && sampleRate == 0) {
    sampleRate = 1000000;
  }
  else if (sampleFreq != 0 && sampleRate != 0) {
    std::fprintf(stderr, "Only one of sample rate/frequency must be given!\n");
    return 1;
  }

  if (sampleRate != 0) {
    ebpf::pyperf::logInfo(1, "Profiling Sample Rate: %" PRIu64 "\n",
                          sampleRate);
  }
  if (sampleFreq != 0) {
    ebpf::pyperf::logInfo(1, "Profiling Sample Frequency: %" PRIu64 "\n",
                          sampleFreq);
  }
  if (duration != 0) {
    ebpf::pyperf::logInfo(1, "Profiling Duration: %" PRIu64 "s\n", duration);
  }

  try {
    ebpf::pyperf::PyPerfProfiler profiler;
    profiler.update_interval = std::chrono::seconds{updateIntervalSecs};

    auto res = profiler.init(symbolsMapSize);
    if (res != ebpf::pyperf::PyPerfProfiler::PyPerfResult::SUCCESS) {
      std::exit((int)res);
    }

    for (auto pid : pids) {
      profiler.pids.push_back(pid);
    }

    g_profiler = &profiler;
    signal(SIGUSR2, on_dump_signal);
    std::fprintf(stderr, "Ready to profile\n");

    ebpf::pyperf::PyPerfCollapsedPrinter printer{output};
    profiler.profile(sampleRate, sampleFreq, duration, &printer);
  }
  catch (const std::exception& e) {
    std::fprintf(stderr, "Profiler error: %s\n", e.what());
    std::exit(1);
  }

  return 0;
}
