/*
 * Copyright (c) Granulate. All rights reserved.
 * Copyright (c) Facebook, Inc.
 *
 * This file has been modified from its original version by Granulate.
 * Modifications are licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include <vector>
#include <utility>
#include <algorithm>

#include "PyPerfType.h"
#include "PyPerfVersion.h"

namespace ebpf {
namespace pyperf {

/*
Struct offsets per Python version.
Most of these fields are named according to the struct name in Python and are defined as structs
whose fields are 64-bit offsets named according the required fields declared in the original struct.
There are a couple of exceptions:
1. String - offsets are into Python string object struct. Since the representation of strings varies
   greatly among versions and depends on encoding and interning, the field names do not correspond
   to the fields of any particular struct. `data` is the offset to the first character of the string,
   and `size` is the offset to the 32-bit integer representing the length in bytes (not characters).
2. PyRuntimeState.interp_main - corresponds to offsetof(_PyRuntimeState, interpreters.main)
3. PyThreadState.thread - this field's name is "thread_id" in some Python versions.
*/

extern const struct struct_offsets kPy27OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        .data = 36,                // offsetof(PyStringObject, ob_sval)
        .size = 16,                // offsetof(PyVarObject, ob_size)
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 0,
        .interp = 8,
        .frame = 16,
        .thread = 144,
    },
    .PyInterpreterState = {
        .tstate_head = 8,
    },
    .PyRuntimeState = {
        .interp_main = -1, // N/A
    },
    .PyFrameObject = {
        .f_back = 24,
        .f_code = 32,
        .f_lineno = 124,
        .f_localsplus = 376,
        .owner = -1,
    },
    .PyCodeObject = {
        .co_filename = 80,
        .co_name = 88,
        .co_varnames = 56,
        .co_firstlineno = 96,
    },
    .PyTupleObject = {
        .ob_item = 24
    }
};

extern const struct struct_offsets kPy36OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        .data = 48,                // sizeof(PyASCIIObject)
        .size = 16,                // offsetof(PyVarObject, ob_size)
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = 24,
        .thread = 152,
    },
    .PyInterpreterState = {
        .tstate_head = 8,
    },
    .PyRuntimeState = {
        .interp_main = -1, // N/A
    },
    .PyFrameObject = {
        .f_back = 24,
        .f_code = 32,
        .f_lineno = 124,
        .f_localsplus = 376,
        .owner = -1,
    },
    .PyCodeObject = {
        .co_filename = 96,
        .co_name = 104,
        .co_varnames = 64,
        .co_firstlineno = 36,
    },
    .PyTupleObject = {
        .ob_item = 24,
    }
};

extern const struct struct_offsets kPy37OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        .data = 48,                // sizeof(PyASCIIObject)
        .size = 16,                // offsetof(PyVarObject, ob_size)
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = 24,
        .thread = 176,
    },
    .PyInterpreterState = {
        .tstate_head = 8,
    },
    .PyRuntimeState = {
        .interp_main = 32,
    },
    .PyFrameObject = {
        .f_back = 24,
        .f_code = 32,
        .f_lineno = 108,
        .f_localsplus = 360,
        .owner = -1,
    },
    .PyCodeObject = {
        .co_filename = 96,
        .co_name = 104,
        .co_varnames = 64,
        .co_firstlineno = 36,
    },
    .PyTupleObject = {
        .ob_item = 24,
    }
};

extern const struct struct_offsets kPy38OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        .data = 48,                // sizeof(PyASCIIObject)
        .size = 16,                // offsetof(PyVarObject, ob_size)
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = 24,
        .thread = 176,
    },
    .PyInterpreterState = {
        .tstate_head = 8,
    },
    .PyRuntimeState = {
        .interp_main = 40,
    },
    .PyFrameObject = {
        .f_back = 24,
        .f_code = 32,
        .f_lineno = 108,
        .f_localsplus = 360,
        .owner = -1,
    },
    .PyCodeObject = {
        .co_filename = 104,
        .co_name = 112,
        .co_varnames = 72,
        .co_firstlineno = 40,
    },
    .PyTupleObject = {
        .ob_item = 24,
    }
};

static const struct struct_offsets kPy39OffsetConfig = kPy38OffsetConfig;

extern const struct struct_offsets kPy310OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        // see https://github.com/python/cpython/blob/3.10/Include/cpython/unicodeobject.h#L82-L84
        .data = 48, // sizeof(PyASCIIObject), which is an offset to string data
        .size = -1, // offsetof(PyVarObject, ob_size)
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = 24,
        .thread = 176,
    },
    .PyInterpreterState = {
        .tstate_head = 8,
    },
    .PyRuntimeState = {
        .interp_main = 40, // N/A
    },
    .PyFrameObject = {
        .f_back = 24,
        .f_code = 32,
        .f_lineno = 100,
        .f_localsplus = 352,
        .owner = -1,
    },
    .PyCodeObject = {
        .co_filename = 104,
        .co_name = 112,
        .co_varnames = 72,
        .co_firstlineno = 40,
    },
    .PyTupleObject = {
        .ob_item = 24
    },
};

extern const struct struct_offsets kPy311OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        // see https://github.com/python/cpython/blob/3.11/Include/cpython/unicodeobject.h#L69-L71
        .data = 48, // sizeof(PyASCIIObject), which is an offset to string data
        .size = 16,
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = -1, // no direct pointer to PyFrameObject since Python 3.11
        .thread = 152, // offsetof(PyThreadState,thread_id),
        .cframe = 56, // pointer to intermediate structure, PyCFrame
    },
    .PyCFrame = {
        .current_frame = 8
    },
    .PyInterpreterState = {
        .tstate_head = 16, // offsetof(PyInterpreterState, threads.head),
    },
    .PyRuntimeState = {
        .interp_main = 48, // offsetof(_PyRuntimeState, interpreters.main),
    },
    .PyFrameObject = { // in Python 3.11 these fields are in PyInterpreterFrame
        .f_back = 48, // offsetof(_PyInterpreterFrame, previous),
        .f_code = 32, // offsetof(_PyInterpreterFrame, f_code),
        .f_lineno = -1, // N/A
        .f_localsplus = 72, // offsetof(_PyInterpreterFrame, localsplus),
        .owner = 69,
    },
    .PyCodeObject = {
        .co_filename = 112,
        .co_name = 120,
        .co_varnames = 96, // offsetof(PyCodeObject, co_localsplusnames),
        .co_firstlineno = 72,
    },
    .PyTupleObject = {
        .ob_item = 24
    },
};

extern const struct struct_offsets kPy312OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        // see https://github.com/python/cpython/blob/3.11/Include/cpython/unicodeobject.h#L69-L71
        .data = 40, // sizeof(PyASCIIObject), which is an offset to string data
        .size = 16,
    },
    .PyTypeObject = {
        .tp_name = 24
    },
    .PyThreadState = {
        .next = 8,
        .interp = 16,
        .frame = -1, // no direct pointer to PyFrameObject since Python 3.11
        .thread = 136, // offsetof(PyThreadState,thread_id),
        .cframe = 56, // pointer to intermediate structure, PyCFrame
    },
    .PyCFrame = {
        .current_frame = 0
    },
    .PyInterpreterState = {
        .tstate_head = 64 + 8, // offsetof(PyInterpreterState, threads.head),
    },
    .PyRuntimeState = {
        .interp_main = 32 + 8 //48, // offsetof(_PyRuntimeState, interpreters.main),
    },
    .PyFrameObject = { // in Python 3.11 these fields are in PyInterpreterFrame
        .f_back = 8, // offsetof(_PyInterpreterFrame, previous),
        .f_code = 0, // offsetof(_PyInterpreterFrame, f_code),
        .f_lineno = -1, // N/A
        .f_localsplus = 72, // offsetof(_PyInterpreterFrame, localsplus),
        .owner = 70,
    },
    .PyCodeObject = {
        .co_filename = 112,
        .co_name = 120,
        .co_varnames = 96, // offsetof(PyCodeObject, co_localsplusnames),
        .co_firstlineno = 68,
    },
    .PyTupleObject = {
        .ob_item = 24
    },
};

/* 3.13:  _PyCFrame was removed and PyThreadState.frame is back.        */
static const struct struct_offsets kPy313OffsetConfig = {
    /* PyObject / String / PyTypeObject */
    .PyObject = { 
        .ob_type = 8 
    },
    .String = { 
        .data = 40, 
        .size = 16 
    },
    .PyTypeObject = { 
        .tp_name = 24 
    },
    /* PyThreadState (frame restored, no cframe) */
    .PyThreadState = { 
        .next = 8, 
        .interp = 16,
        .frame = 72,
        .thread = 152,
        .cframe = -1 },
    /* _PyCFrame is gone */
    .PyCFrame      = { 
        .current_frame = -1 
    },
    /* Interpreter / runtime */
    .PyInterpreterState = { 
        .tstate_head = 7344 
    },
    .PyRuntimeState = {
        .interp_main = 640
    },
    /* _PyInterpreterFrame “virtual” frame */
    .PyFrameObject = { 
        .f_back = 8,
        .f_code = 0,
        .f_lineno = -1,
        .f_localsplus = 72,
        .owner = 70,
    },
    /* PyCodeObject offsets unchanged since 3.11 */
    .PyCodeObject = {
        .co_filename = 112,
        .co_name = 120,
        .co_varnames = 96,
        .co_firstlineno = 68
    },
    .PyTupleObject = {
        .ob_item = 24
    },
};

// List of mappings from Python 3 minor versions to offsets. `get_offsets` depends on this list
// being sorted in ascending order when it searches through it.
const std::vector<std::pair<version, struct_offsets>> python3Versions = {
    {{3,6,0}, kPy36OffsetConfig},
    {{3,7,0}, kPy37OffsetConfig},
    {{3,8,0}, kPy38OffsetConfig},
    {{3,9,0}, kPy39OffsetConfig},
    {{3,10,0}, kPy310OffsetConfig},
    {{3,11,0}, kPy311OffsetConfig},
    {{3,12,0}, kPy312OffsetConfig},
    {{3,13,0}, kPy313OffsetConfig},
};

const struct_offsets& get_offsets(version& version) {
  if (version.major == 2) {
    return kPy27OffsetConfig;
  }
  else {
    // Find offsets for Python 3 version:
    auto it = std::find_if(python3Versions.crbegin(), python3Versions.crend(), [&](auto item){
      return item.first <= version;
    });
    return it->second;
  }
}

}
}  // namespace ebpf
