/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include <string>

namespace ebpf {
namespace pyperf {

extern const std::string PYPERF_BPF_PROGRAM = R"(
#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define BAD_THREAD_ID (~0)

// Maximum threads: 32x8 = 256
#define THREAD_STATES_PER_PROG 32
#define THREAD_STATES_PROG_CNT 8

// Maximum Python stack frames: 20x4 = 80
#define PYTHON_STACK_FRAMES_PER_PROG 20
#define PYTHON_STACK_PROG_CNT 4
#define STACK_MAX_LEN (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT)

#define CLASS_NAME_LEN 32
#define FUNCTION_NAME_LEN 64
#define FILE_NAME_LEN 128
#define TASK_COMM_LEN 16

/**
See PyPerfType.h
*/
enum error_code {
  ERROR_NONE = 0,
  ERROR_MISSING_PYSTATE = 1,
  ERROR_THREAD_STATE_NULL = 2,
  ERROR_INTERPRETER_NULL = 3,
  ERROR_TOO_MANY_THREADS = 4,
  ERROR_THREAD_STATE_NOT_FOUND = 5,
  ERROR_EMPTY_STACK = 6,
  ERROR_FRAME_CODE_IS_NULL = 7,
  ERROR_BAD_FSBASE = 8,
  ERROR_INVALID_PTHREADS_IMPL = 9,
  ERROR_THREAD_STATE_HEAD_NULL = 10,
  ERROR_BAD_THREAD_STATE = 11,
};

/**
See PyPerfType.h
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

struct pid_data {
  enum pthreads_impl pthreads_impl;
  struct py_globals globals;
  struct struct_offsets offsets;
  uintptr_t interp;  // vaddr of PyInterpreterState
};

/**
Contains all the info we need for a stack frame.

Storing `classname` and `file` here means these are duplicated for symbols in the same class or
file. This can be avoided with additional maps but it's ok because generally speaking symbols are
spread across a variety of files and classes. Using a separate map for `name` would be useless
overhead because symbol names are mostly unique.
*/
struct symbol {
  char classname[CLASS_NAME_LEN];
  char name[FUNCTION_NAME_LEN];
  char file[FILE_NAME_LEN];
  // NOTE: PyFrameObject also has line number but it is typically just the
  // first line of that function and PyCode_Addr2Line needs to be called
  // to get the actual line
};

/**
Represents final event data passed to user-mode driver.
*/
struct event {
  uint32_t pid;
  uint32_t tid;
  char comm[TASK_COMM_LEN];
  uint8_t error_code;
  uint8_t stack_status;
  int32_t kernel_stack_id;
  // instead of storing symbol name here directly, we add it to another
  // hashmap with Symbols and only store the ids here
  uint32_t stack_len;
  int32_t stack[STACK_MAX_LEN];
};

struct sample_state {
  uint64_t current_thread_id;
  uintptr_t constant_buffer_addr;
  uintptr_t interp_head;
  uintptr_t thread_state;
  struct struct_offsets offsets;
  uint64_t cur_cpu;
  int get_thread_state_call_count;
  int64_t symbol_counter;
  void* frame_ptr;
  int python_stack_prog_call_cnt;
  struct event event;
};

// Hashtable of stack frame to unique id. Storing all symbol data all the
// time would quickly inflate the output buffer. See `get_symbol_id`,
BPF_HASH(symbols, struct symbol, int32_t, __SYMBOLS_SIZE__);

// Table of processes currently being profiled.
BPF_HASH(pid_config, pid_t, struct pid_data);

// Contains fd's of get_thread_state and read_python_stack programs.
BPF_PROG_ARRAY(progs, 2);

BPF_PERCPU_ARRAY(state_heap, struct sample_state, 1);
BPF_PERF_OUTPUT(events);

BPF_STACK_TRACE(kernel_stacks, __KERNEL_STACKS_SIZE__);

/**
Get the thread id for a task just as Python would. Currently assumes Python uses pthreads.
*/
static __always_inline int
get_task_thread_id(struct task_struct const *task, enum pthreads_impl pthreads_impl, uint64_t *thread_id) {
  // The thread id that is written in the PyThreadState is the value of `pthread_self()`.
  // For glibc, corresponds to THREAD_SELF in "tls.h" in glibc source.
  // For musl, see definition of `__pthread_self`.

#ifdef __x86_64__
// thread_struct->fs was renamed to fsbase in
// https://github.com/torvalds/linux/commit/296f781a4b7801ad9c1c0219f9e87b6c25e196fe
// so depending on kernel version, we need to account for that
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define THREAD_FSBASE(task) (task->thread.fs)
#else
#define THREAD_FSBASE(task) (task->thread.fsbase)
#endif

  int ret;
  uint64_t fsbase;
  // HACK: Usually BCC would translate a deref of the field into `read_kernel` for us, but it
  //       doesn't detect it due to the macro (because it transforms before preprocessing).
  bpf_probe_read_kernel(&fsbase, sizeof(fsbase), &THREAD_FSBASE(task));

  switch (pthreads_impl) {
  case PTI_GLIBC:
    // 0x10 = offsetof(tcbhead_t, self)
    ret = bpf_probe_read_user(thread_id, sizeof(*thread_id), (void *)(fsbase + 0x10));
    break;

  case PTI_MUSL:
    // __pthread_self / __get_tp reads %fs:0x0
    // which corresponds to the field "self" in struct pthread
    ret = bpf_probe_read_user(thread_id, sizeof(*thread_id), (void *)fsbase);
    break;

  default:
    // driver passed bad value
    return ERROR_INVALID_PTHREADS_IMPL;
  }

  if (ret < 0) {
    return ERROR_BAD_FSBASE;
  }

  return ERROR_NONE;

#else  // __x86_64__
#error "Unsupported platform"
#endif // __x86_64__
}

// this function is trivial, but we need to do map lookup in separate function,
// because BCC doesn't allow direct map calls (including lookups) from inside
// a macro (which we want to do in GET_STATE() macro below)
static __always_inline struct sample_state* get_state() {
  int zero = 0;
  return state_heap.lookup(&zero);
}

#define GET_STATE(state) \
  struct sample_state *state = get_state(); \
  if (!state) { \
    /* assuming state_heap is at least size 1, this can't happen */ \
    return 0; \
  }

/**
Get a PyThreadState's thread id.
*/
static __always_inline uint64_t
read_tstate_thread_id(uintptr_t thread_state, struct struct_offsets *offsets) {
    uint64_t thread_id;
    int ret = bpf_probe_read_user(&thread_id, sizeof(thread_id),
                                  (void *)(thread_state + offsets->PyThreadState.thread));
    if (ret < 0) {
      return BAD_THREAD_ID;
    }
    return thread_id;
}

/**
Gets called on every perf event
*/
int
on_event(struct pt_regs* ctx) {
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = (pid_t)(pid_tgid >> 32);
  struct pid_data *pid_data = pid_config.lookup(&pid);
  if (!pid_data) {
    return 0;
  }

  GET_STATE(state);
  struct event* event = &state->event;
  event->pid = pid;
  event->tid = (pid_t)pid_tgid;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  if (pid_data->interp == 0) {
    // This is the first time we sample this process (or the GIL is still released).
    // Let's find PyInterpreterState:
    uintptr_t interp_ptr;
    if (pid_data->globals._PyRuntime) {
      interp_ptr = pid_data->globals._PyRuntime + pid_data->offsets.PyRuntimeState.interp_main;
    }
    else {
      if (!pid_data->globals._PyThreadState_Current) {
        event->error_code = ERROR_MISSING_PYSTATE;
        goto submit;
      }

      // Get PyThreadState of the thread that currently holds the GIL
      uintptr_t _PyThreadState_Current = 0;
      bpf_probe_read_user(
          &_PyThreadState_Current, sizeof(_PyThreadState_Current),
          (void*)pid_data->globals._PyThreadState_Current);
      if (_PyThreadState_Current == 0) {
        // The GIL is released, we can only get native stacks
        // until it is held again.
        // TODO: mark GIL state = released in event
        event->error_code = ERROR_THREAD_STATE_NULL;
        goto submit;
      }

      // Read the interpreter pointer from the ThreadState:
      interp_ptr = _PyThreadState_Current + pid_data->offsets.PyThreadState.interp;
    }

    bpf_probe_read_user(&pid_data->interp, sizeof(pid_data->interp), (void *)interp_ptr);
    if (unlikely(pid_data->interp == 0)) {
      event->error_code = ERROR_INTERPRETER_NULL;
      goto submit;
    }
  }

  // Get current thread id:
  struct task_struct const *const task = (struct task_struct *)bpf_get_current_task();
  event->error_code = get_task_thread_id(task, pid_data->pthreads_impl, &state->current_thread_id);
  if (event->error_code != ERROR_NONE) {
    goto submit;
  }

  // Copy some required info:
  state->offsets = pid_data->offsets;
  state->interp_head = pid_data->interp;
  state->constant_buffer_addr = pid_data->globals.constant_buffer;

  // Read pointer to first PyThreadState in thread states list:
  bpf_probe_read_user(
    &state->thread_state, sizeof(state->thread_state),
    (void *)(state->interp_head + pid_data->offsets.PyInterpreterState.tstate_head));
  if (state->thread_state == 0) {
    event->error_code = ERROR_THREAD_STATE_HEAD_NULL;
    goto submit;
  }

  // Call get_thread_state to find the PyThreadState of this thread:
  event->error_code = ERROR_THREAD_STATE_NOT_FOUND;
  state->get_thread_state_call_count = 0;
  progs.call(ctx, GET_THREAD_STATE_PROG_IDX);

submit:
  events.perf_submit(ctx, &state->event, sizeof(struct event));
  return 0;
}

/**
Searches through all the PyThreadStates in the interpreter to find the one
corresponding to the current task. Once found, call `read_python_stack`.
If not found, submit an event containing the error.
*/
int
get_thread_state(struct pt_regs *ctx) {
  GET_STATE(state);
  struct event* event = &state->event;
  uint64_t thread_id;

  state->get_thread_state_call_count++;

#pragma unroll
  for (int i = 0; i < THREAD_STATES_PER_PROG; ++i) {
    // Read the PyThreadState::thread_id to which this PyThreadState belongs:
    thread_id = read_tstate_thread_id(state->thread_state, &state->offsets);
    if (thread_id == state->current_thread_id) {
      goto found;
    }
    else if (unlikely(thread_id == BAD_THREAD_ID)) {
      goto bad_thread_state;
    }
    // Read next thread state:
    bpf_probe_read_user(
      &state->thread_state, sizeof(state->thread_state),
      (void *)(state->thread_state + state->offsets.PyThreadState.next));
    if (state->thread_state == 0) {
      // ERROR_THREAD_STATE_NOT_FOUND is set in on_event before the call
      goto submit;
    }
  }

  if (state->get_thread_state_call_count == THREAD_STATES_PROG_CNT) {
    event->error_code = ERROR_TOO_MANY_THREADS;
    goto submit;
  }

  progs.call(ctx, GET_THREAD_STATE_PROG_IDX);
  // <unreachable>

found:
  // Get pointer to top frame from PyThreadState
  bpf_probe_read_user(
      &state->frame_ptr, sizeof(state->frame_ptr),
      (void *)(state->thread_state + state->offsets.PyThreadState.frame));
  if (state->frame_ptr == 0) {
    event->error_code = ERROR_EMPTY_STACK;
    goto submit;
  }

  // Reset the error code
  event->error_code = ERROR_NONE;

  // Initialize stack info in case any subprogram below fails
  event->stack_status = STACK_STATUS_ERROR;
  event->stack_len = 0;

  // We are going to need this later
  state->cur_cpu = bpf_get_smp_processor_id();

  // Jump to reading first set of Python frames
  state->python_stack_prog_call_cnt = 0;
  progs.call(ctx, PYTHON_STACK_PROG_IDX);
  // <unreachable>

bad_thread_state:
  event->error_code = ERROR_BAD_THREAD_STATE;
submit:
  events.perf_submit(ctx, &state->event, sizeof(struct event));
  return 0;
}

static __always_inline void
clear_symbol(struct sample_state *state, struct symbol *sym) {
  // Helper bpf_perf_prog_read_value clears the buffer on error, so we can
  // take advantage of this behavior to clear the memory. It requires the size of
  // the buffer to be different from struct bpf_perf_event_value.
  //
  // bpf_perf_prog_read_value(ctx, symbol, sizeof(struct symbol));

  // That API was introduced in kernel ver. 4.15+, so the alternative is to
  // copy a constant buffer from somewhere.
  bpf_probe_read_user(sym, sizeof(*sym), (void *)state->constant_buffer_addr);
}

/**
Reads the name of the first argument of a PyCodeObject.
*/
static __always_inline void
get_first_arg_name(
  void *code_ptr,
  struct struct_offsets *offsets,
  char *argname,
  size_t maxlen) {
  // Roughly equivalnt to the following in GDB:
  //
  //   ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
  //
  void* args_ptr;
  bpf_probe_read_user(&args_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject.co_varnames);
  bpf_probe_read_user(&args_ptr, sizeof(void*), args_ptr + offsets->PyTupleObject.ob_item);
  bpf_probe_read_user_str(argname, maxlen, args_ptr + offsets->String.data);
}

/**
Read the name of the class wherein a code object is defined.
For global functions, sets an empty string.
*/
static __always_inline void
get_classname(
  struct struct_offsets *offsets,
  void *cur_frame,
  void *code_ptr,
  struct symbol *symbol) {
  // Figure out if we want to parse class name, basically checking the name of
  // the first argument. If it's 'self', we get the type and it's name, if it's
  // 'cls', we just get the name. This is not perfect but there is no better way
  // to figure this out from the code object.
  char argname[5]; // sizeof('self') + 1
  get_first_arg_name(code_ptr, offsets, argname, sizeof(argname));

  // compare strings as ints to save instructions
  static char self_str[4] = {'s', 'e', 'l', 'f'};
  static char cls_str[4] = {'c', 'l', 's', '\0'};
  bool first_self = *(int32_t*)argname == *(int32_t*)self_str && argname[4] == '\0';
  bool first_cls = *(int32_t*)argname == *(int32_t*)cls_str;

  // Read class name from $frame->f_localsplus[0]->ob_type->tp_name.
  if (first_self || first_cls) {
    void* tmp;
    // read f_localsplus[0]:
    bpf_probe_read_user(&tmp, sizeof(void*), cur_frame + offsets->PyFrameObject.f_localsplus);
    if (first_self) {
      // we are working with an instance, first we need to get type
      bpf_probe_read_user(&tmp, sizeof(void*), tmp + offsets->PyObject.ob_type);
    }
    bpf_probe_read_user(&tmp, sizeof(void*), tmp + offsets->PyTypeObject.tp_name);
    bpf_probe_read_user_str(&symbol->classname, sizeof(symbol->classname), tmp);
  }
  else {
    symbol->classname[0] = '\0';
  }
}

static __always_inline void
get_symbol_names(
    struct struct_offsets *offsets,
    void* cur_frame,
    void* code_ptr,
    struct symbol* symbol) {
  get_classname(offsets, cur_frame, code_ptr, symbol);

  void* pystr_ptr;
  // read PyCodeObject's filename into symbol
  bpf_probe_read_user(&pystr_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject.co_filename);
  bpf_probe_read_user_str(&symbol->file, sizeof(symbol->file), pystr_ptr + offsets->String.data);
  // read PyCodeObject's name into symbol
  bpf_probe_read_user(&pystr_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject.co_name);
  bpf_probe_read_user_str(&symbol->name, sizeof(symbol->name), pystr_ptr + offsets->String.data);
}

static __always_inline int64_t
get_symbol_id(
    struct sample_state* state,
    struct symbol* sym) {
  int32_t* symbol_id_ptr = symbols.lookup(sym);
  if (symbol_id_ptr) {
    return *symbol_id_ptr;
  }
  // the symbol is new, bump the counter
  // To avoid duplicate ids, every CPU needs to use different ids when inserting
  // into the hashmap. NUM_CPUS is defined at PyPerf backend side and passed
  // through CFlag.
  int32_t symbol_id = state->symbol_counter * NUM_CPUS + state->cur_cpu;
  state->symbol_counter++;
  symbols.update(sym, &symbol_id);
  return symbol_id;
}

int read_python_stack(struct pt_regs* ctx) {
  GET_STATE(state);
  struct event *event = &state->event;
  struct symbol sym = {};
  bool last_res = false;
  void *cur_frame;
  void *cur_code_ptr;

  state->python_stack_prog_call_cnt++;

#pragma unroll
  for (int i = 0; i < PYTHON_STACK_FRAMES_PER_PROG; i++) {
    // We re-use the same struct symbol instance across loop iterations, which means
    // we will have left-over data in the struct. Although this won't affect
    // correctness of the result because we have '\0' at end of the strings read,
    // it would affect effectiveness of the deduplication.
    clear_symbol(state, &sym);

    cur_frame = state->frame_ptr;

    // read PyCodeObject first, if that fails, then no point reading next frame
    bpf_probe_read_user(
        &cur_code_ptr, sizeof(cur_code_ptr),
        cur_frame + state->offsets.PyFrameObject.f_code);
    if (!cur_code_ptr) {
      goto no_code;
    }

    // read current PyFrameObject filename/name
    get_symbol_names(&state->offsets, cur_frame, cur_code_ptr, &sym);
    uint32_t symbol_id = get_symbol_id(state, &sym);
    uint32_t cur_len = event->stack_len;
    if (cur_len < STACK_MAX_LEN) {
      event->stack[cur_len] = symbol_id;
      event->stack_len++;
    }

    // read next PyFrameObject pointer, update in place
    bpf_probe_read_user(
        &state->frame_ptr, sizeof(state->frame_ptr),
        cur_frame + state->offsets.PyFrameObject.f_back);
    if (!state->frame_ptr) {
      goto complete;
    }
  }

  if (state->python_stack_prog_call_cnt < PYTHON_STACK_PROG_CNT) {
    // read next batch of frames
    progs.call(ctx, PYTHON_STACK_PROG_IDX);
    // <unreachable>
  }
  else {
    event->stack_status = STACK_STATUS_TRUNCATED;
    goto submit;
  }

no_code:
  event->error_code = ERROR_FRAME_CODE_IS_NULL;
  goto submit;

complete:
  event->kernel_stack_id = kernel_stacks.get_stackid(ctx, BPF_F_REUSE_STACKID);
  event->error_code = ERROR_NONE;
  event->stack_status = STACK_STATUS_COMPLETE;
submit:
  events.perf_submit(ctx, &state->event, sizeof(struct event));
  return 0;
}
)";
}
}  // namespace ebpf
