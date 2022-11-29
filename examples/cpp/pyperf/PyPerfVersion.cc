/*
 * Copyright (c) Granulate. All rights reserved.
 * Licensed under the AGPL3 License. See LICENSE.txt for license information.
 */

#include "PyPerfVersion.h"
#include <regex>
#include <cstdio>
#include <cstring>
#include <unistd.h>

namespace ebpf {
namespace pyperf {

bool operator<=(version a, version b) {
  if (a.major == b.major) {
    if (a.minor == b.minor) {
      return a.patch <= b.patch;
    }
    return a.minor <= b.minor;
  }
  return a.major <= b.major;
}

/**
Given a major.minor version string in `filever`, searches for the full major.minor.patch version of
Python in the file given by `python_fd`. The result is returned in `version`.
`version` should be zeroed before calling this function.
*/
bool get_python_version(int python_fd, std::string& filever, version& version) {
  std::string tmp;

  // Build the version regex
  tmp = filever;
  // escape the period after the major (before the minor):
  tmp.insert(1, R"(\)");
  tmp += R"(\.[0-9]+\b)";
  std::regex version_re{tmp};

  // dup so we don't change the original fd position
  int fd = dup(python_fd);
  if (fd < 0) {
    return false;
  }

  // Searching happens in a "sliding buffer" that consists of two consecutive blocks. Each block is
  // at most one half of the entire buffer but may be smaller. We do this so we don't miss a match
  // that starts at the end of one block but ends at the beginning of the next block.
  // 1. "Slide" the trailing block to the beginning of the buffer. It's now the leading block.
  // 2. Read a block into the buffer after the leading block. This is now the trailing block.
  // 3. The two blocks are now consecutive. Search the buffer until the end of the trailing block.
  //    If found, done.
  // Of course, no need to slide on the first iteration (because we haven't read anything yet), so
  // the actual order of the steps in the loop is 2->3->1.
  static char buf[BUFSIZ * 2];
  FILE *f = fdopen(fd, "rb");
  for (size_t read1 = 0; ;) {
    // Read
    size_t read2 = fread(buf + read1, 1, BUFSIZ, f);
    if (read2 != BUFSIZ) {
      break;
    }
    // Search
    std::string s{buf, read1 + read2};
    std::smatch results;
    if (std::regex_search(s, results, version_re)) {
      tmp = results.str();
      break;
    }
    // Slide
    memmove(buf, buf + read1, read2);
    read1 = read2;
  };
  fclose(f);

  int count = sscanf(tmp.c_str(), "%u.%u.%u", &version.major, &version.minor, &version.patch);
  if (count != 2 && count != 3) {
    return false;
  }
  return true;
}

}  // namespace pyperf
}  // namespace ebpf
