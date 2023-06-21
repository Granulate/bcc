# Copyright (c) Granulate. All rights reserved.
# Copyright (c) Facebook, Inc.
#
# This file has been modified from its original version by Granulate.
# Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
#
include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)

add_executable(PyPerf
        PyPerf.cc
        PyPerfProfiler.cc
        PyPerfBPFProgram.cc
        PyPerfLoggingHelper.cc
        PyPerfCollapsedPrinter.cc
        PyPerfVersion.cc
        PyPerfProc.cc
        PyOffsets.cc
        PyPerfNativeStackTrace.cc
        )
target_link_libraries(PyPerf pthread libunwind-ptrace.a)

execute_process(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)

if(${ARCHITECTURE} STREQUAL "x86_64")
    target_link_libraries(PyPerf libunwind-x86_64.a)
elseif(${ARCHITECTURE} STREQUAL "aarch64")
    target_link_libraries(PyPerf libunwind-aarch64.a)
endif()
target_link_libraries(PyPerf libunwind.a)  # this one is needed after the x86_64/aarch64 link

target_link_libraries(PyPerf lzma)

if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  target_link_libraries(PyPerf bcc-static)
else()
  target_link_libraries(PyPerf bcc-shared)
endif()

if(INSTALL_CPP_EXAMPLES)
  install (TARGETS PyPerf DESTINATION share/bcc/examples/cpp)
endif(INSTALL_CPP_EXAMPLES)
