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

extern const struct struct_offsets kPy310OffsetConfig = {
    .PyObject = {
        .ob_type = 8
    },
    .String = {
        .data = 48,                // offsetof(PyStringObject, ob_sval)
        .size = -1,                // offsetof(PyVarObject, ob_size)
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

// List of mappings from Python 3 minor versions to offsets. `get_offsets` depends on this list
// being sorted in ascending order when it searches through it.
const std::vector<std::pair<version, struct_offsets>> python3Versions = {
    {{3,6,0}, kPy36OffsetConfig},
    {{3,7,0}, kPy37OffsetConfig},
    {{3,8,0}, kPy38OffsetConfig},
    // 3.9 is same as 3.8
    {{3,10,0}, kPy310OffsetConfig},
};

const struct_offsets& get_offsets(version& version) {
  if (version.major == 2) {
    return kPy27OffsetConfig;
  }
  else {
    // Find offsets for Python 3 version:
    auto it = std::find_if(python3Versions.crbegin(), python3Versions.crend(), [&](auto item){
      return item.first < version;
    });
    return it->second;
  }
}

}
}  // namespace ebpf
