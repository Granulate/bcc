/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */
#pragma once

#include <string>

namespace ebpf {
namespace pyperf {

struct version {
  unsigned int major, minor, patch;
};

bool operator<=(version a, version b);

bool get_python_version(int python_fd, std::string& filever, version& version);

}  // namespace pyperf
}  // namespace ebpf
