/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @file utils.c
 * @brief Utility functions.
 */

#include "utils.h"

/**
 * @brief Create all ancestor directories of given path.
 *
 * @param path input path
 *
 * @return true if successful, false otherwise
 */
bool path_create_ancestors(char *path) {
  char *p = path;
  char *pprev = NULL;
  while ((pprev = p), (p = strchr(p, '/'))) {
    ++p;
    // Ignore if the segment is empty
    if ((p - pprev) <= 1)
      continue;
    char c = *p;
    *p = '\0';
    if (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) && EEXIST != errno) {
      printf_errf("(): Failed to create directory %s: %d", path, errno);
      return false;
    }
    *p = c;
  }

  return true;
}

