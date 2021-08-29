/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 *
 * Definitions common to the user-mode driver and the BPF module.
 * Currently, these have to be manually synchronized from the BPF module source.
 *
 * TODO: Define these definitions in one C header file, and sync them automatically
 *       at build time.
 */

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "PyPerfNativeStackTrace.h"

namespace ebpf {
namespace pyperf {

// See BPF source for meaning of these values
#define PYTHON_STACK_FRAMES_PER_PROG 20
#define PYTHON_STACK_PROG_CNT 4
#define STACK_MAX_LEN (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT)
#define CLASS_NAME_LEN 32
#define FUNCTION_NAME_LEN 64
#define FILE_NAME_LEN 256
#define TASK_COMM_LEN 16

/**
ERROR_NONE: No error

ERROR_MISSING_PYSTATE:
  Expected one of _PyThreadState_Current/_PyRuntime to be set, but both are NULL.

ERROR_THREAD_STATE_NULL:
  Read _PyThreadState_Current and it's NULL. This means the GIL is released, and we have to wait
  until it is grabbed again to get the PyInterpreterState.

ERROR_INTERPRETER_NULL:
  Read the address of PyInterpreterState from _PyThreadState_Current/_PyRuntime and got NULL.
  This can happen at process startup/shutdown when the interpreter hasn't been created yet or has been
  torn down.

ERROR_TOO_MANY_THREADS:
  When searching for the PyThreadState, we iterated through the maximum thread states and didn't find
  a match. Increase the maximum number of thread states to iterate.

ERROR_THREAD_STATE_NOT_FOUND:
  When searching for the PyThreadState, we iterated through _all_ the thread states and didn't find
  a match.

ERROR_EMPTY_STACK:
  The frame pointer in the current PyThreadState is NULL, meaning the Python stack for this Python
  thread is empty.

ERROR_BAD_FSBASE:
  Reading data from the thread descriptor (at %fs) faulted. This can happen when a new thread is created but pthreads
  has not initialized in that thread yet.

ERROR_INVALID_PTHREADS_IMPL:
  The pthreads implementation set for the process is invalid.

ERROR_THREAD_STATE_HEAD_NULL:
  Read the pointer to the head of the thread states list from the PyInterpreterState and got NULL.

ERROR_BAD_THREAD_STATE:
  Reading a field from a thread state in the thread states list failed.

ERROR_CALL_FAILED:
  A tail call to a BPF program failed.
*/
enum error_code {
  ERROR_NONE = 0,
  ERROR_MISSING_PYSTATE = 1,
  ERROR_THREAD_STATE_NULL = 2,
  ERROR_INTERPRETER_NULL = 3,
  ERROR_TOO_MANY_THREADS = 4,
  ERROR_THREAD_STATE_NOT_FOUND = 5,
  ERROR_EMPTY_STACK = 6,
  // ERROR_FRAME_CODE_IS_NULL = 7,
  ERROR_BAD_FSBASE = 8,
  ERROR_INVALID_PTHREADS_IMPL = 9,
  ERROR_THREAD_STATE_HEAD_NULL = 10,
  ERROR_BAD_THREAD_STATE = 11,
  ERROR_CALL_FAILED = 12,
};

/**
STACK_STATUS_COMPLETE:
  Read all the Python stack frames for the running thread, from first to last.

STACK_STATUS_ERROR:
  Failed to read a stack frame.

STACK_STATUS_TRUNCATED:
  Succeeded in reading the top STACK_MAX_LEN stack frames, and there were more frames
  we didn't read. Try incrementing PYTHON_STACK_PROG_CNT.
*/
enum stack_status {
  STACK_STATUS_COMPLETE = 0,
  STACK_STATUS_ERROR = 1,
  STACK_STATUS_TRUNCATED = 2,
};

/**
Identifies the POSIX threads implementation used by a Python process.
*/
enum pthreads_impl {
  PTI_GLIBC = 0,
  PTI_MUSL = 1,
};

/**
See PyOffsets.cc
*/
struct struct_offsets {
  struct {
    int64_t ob_type;
  } PyObject;
  struct {
    int64_t data;
    int64_t size;
  } String;
  struct {
    int64_t tp_name;
  } PyTypeObject;
  struct {
    int64_t next;
    int64_t interp;
    int64_t frame;
    int64_t thread;
  } PyThreadState;
  struct {
    int64_t tstate_head;
  } PyInterpreterState;
  struct {
    int64_t interp_main;
  } PyRuntimeState;
  struct {
    int64_t f_back;
    int64_t f_code;
    int64_t f_lineno;
    int64_t f_localsplus;
  } PyFrameObject;
  struct {
    int64_t co_filename;
    int64_t co_name;
    int64_t co_varnames;
    int64_t co_firstlineno;
  } PyCodeObject;
  struct {
    int64_t ob_item;
  } PyTupleObject;
};

struct py_globals {
  /*
  This struct contains offsets when used in the offsets map,
  and resolved vaddrs when used in the pid_data map.
  */
  uint64_t constant_buffer;  // arbitrary constant offset
  uint64_t _PyThreadState_Current; // 3.6-
  uint64_t _PyRuntime;  // 3.7+
};

/**
See BPF source.
*/
struct uprobe_id {
  uint64_t ip_buf[16];
  uint16_t ip;
};

/**
See BPF source.
*/
struct exec_offsets {
  enum pthreads_impl pthreads_impl;
  struct py_globals globals;
  struct struct_offsets structs;
};

typedef struct pid_data {
  enum pthreads_impl pthreads_impl;
  struct py_globals globals;
  struct struct_offsets offsets;
  uintptr_t interp;  // vaddr of PyInterpreterState
} PidData;

/**
See BPF source.
*/
typedef struct symbol {
  uint32_t lineno;
  char classname[CLASS_NAME_LEN];
  char name[FUNCTION_NAME_LEN];
  char file[FILE_NAME_LEN];
} Symbol;

typedef struct event {
  uint32_t pid;
  uint32_t tid;
  char comm[TASK_COMM_LEN];
  uint8_t error_code;
  uint8_t stack_status;
  int32_t kernel_stack_id;
  // instead of storing symbol name here directly, we add it to another
  // hashmap with Symbols and only store the ids here
  int32_t stack_len;
  int32_t stack[STACK_MAX_LEN];
#define FRAME_CODE_IS_NULL ((int32_t)0x80000001)
  uintptr_t user_ip;
  uintptr_t user_sp;
  uint32_t user_stack_len;
  uint8_t raw_user_stack[]; // NOTICE: Field with variadic length - must be last!
} Event;

struct PyPerfSample {
  pid_t pid;
  pid_t tid;
  std::string comm;
  uint8_t errorCode;
  uint8_t stackStatus;
  int32_t kernelStackId;
  std::vector<int32_t> pyStackIds;
  NativeStackTrace nativeStack;

  explicit PyPerfSample(const Event* raw, int rawSize)
      : pid(raw->pid),
        tid(raw->tid),
        comm(raw->comm),
        errorCode(raw->error_code),
        stackStatus(raw->stack_status),
        kernelStackId(raw->kernel_stack_id),
        pyStackIds(raw->stack, raw->stack + raw->stack_len),
        nativeStack(raw->pid, raw->raw_user_stack, raw->user_stack_len,
                    raw->user_ip, raw->user_sp) {}
};

}  // namespace pyperf
}  // namespace ebpf
