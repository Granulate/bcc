# pyperf

**pyperf** is a sampling profiler for Python with very minimal overhead.

It works with Python 2.7, and 3.6 through 3.9.

## Usage:

```
PyPerf [-p|--pid PID]
       [-F|--frequency HZ]
       [-d|--duration SECONDS]
       [--update-interval SECONDS]
       [--symbols-map-size SIZE]
       [--events-buffer-pages PAGES]
       [--kernel-stacks-map-size SIZE]
       [--user-stacks-pages PAGES]
       [-v|--verbose VERBOSITY]
       [-o|--output FILENAME]
       [--fs-offset OFFSET]
       [--stack-offset OFFSET]
```

A FlameGraph-style stackcollapse listing is written to the output filename (or standard output if
not specified). You can use standard FlameGraph tools to visualize the result.

_Requires running as root._

## Features:

* Supports profiling Python processes running in Docker containers. Tested using official Python
  Docker images (`python:X.Y`).
* Supports glibc- and musl-based environments.
* Supports Python compiled in both PIE and non-PIE configurations.
* Supports Python running standalone and as a library (linked with `libpythonX.Y`).

## Limitations:

* Architecture: x86_64.
* Linux kernel version: oldest version tested is 4.14. Versions 4.11-4.14 may work. Required for
  `bpf_probe_read_str`.
* BCC version: using BCC nightly is recommended. v0.17 is known to work.
* Clang/LLVM: at least version 9.

## Overview

PyPerf uses Linux's perf events subsystem to gather stack samples of running Python interpreters at
a constant interval. Instead of capturing native execution stacks, PyPerf reads the information
stored by the Python interpreter regarding the current state of execution. Unlike many existing
tools however, the memory of the process is read from a kernel context. The advantages of this
approach are mainly reduced system overhead and no intervention with the program being profiled.
