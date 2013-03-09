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
      printf_errf("(): Failed to create directory %s: %d (%s)", path, errno,
          dumpstr_errno());
      return false;
    }
    *p = c;
  }

  return true;
}

/**
 * @brief Return a char representing a file type.
 */
static inline char dumpchr_stat_file_type(mode_t mode) {
#define IFRETVAL(cond, val) { if (cond) return (val); }
  IFRETVAL(S_ISDIR(mode), 'd');
  IFRETVAL(S_ISCHR(mode), 'c');
  IFRETVAL(S_ISBLK(mode), 'b');
  IFRETVAL(S_ISREG(mode), '-');
  IFRETVAL(S_ISFIFO(mode), 'p');
  IFRETVAL(S_ISLNK(mode), 'l');
  IFRETVAL(S_ISSOCK(mode), 's');

  return '?';
}

/**
 * @brief Dump permissions of a file.
 */
static inline void dump_stat_perms(FILE *stream, mode_t mode) {
  char perm_str[] = "---------";
  char *pc = perm_str;
#define MASK_TEST_SETC(mask, c) { \
  if (mode & mask) \
    *pc = c; \
  ++pc; \
}

  MASK_TEST_SETC(S_IRUSR, 'r');
  MASK_TEST_SETC(S_IWUSR, 'w');
  MASK_TEST_SETC(S_IXUSR, 'x');
  MASK_TEST_SETC(S_IRGRP, 'r');
  MASK_TEST_SETC(S_IWGRP, 'w');
  MASK_TEST_SETC(S_IXGRP, 'x');
  MASK_TEST_SETC(S_IROTH, 'r');
  MASK_TEST_SETC(S_IWOTH, 'w');
  MASK_TEST_SETC(S_IXOTH, 'x');
#undef BAND_TEST_SETC

  assert(!*pc);

  fputs(perm_str, stream);
}

/**
 * @brief Dump time in a human-readable format
 *
 * @param stream output stream
 * @param tm time
 */
static inline void dump_time(FILE *stream, time_t tm) {
  // Stolen from coreutils-8.21
  char str[(INT_STRLEN_BOUND(int) // YYYY
      + 1 // because YYYY might equal INT_MAX + 1900
      + sizeof("-MM-DD HH:MM"))];

  struct tm const *ltm = localtime(&tm);
  if (!strftime(str, sizeof(str), "%Y-%m-%d %H:%M", ltm))
    return;
  fputs(str, stream);
}

/**
 * @brief Dump a size in a human-readable format.
 *
 * @param stream output stream to print to
 * @param unum the size
 * @param width minimal field width
 */
static inline void dump_sz_human(FILE *stream, uintmax_t unum, int width) {
  char postfix = '\0';

  // Make sure the width is at least 1
  width = max_i(width, 1);

  // Determine postfix
#define SET_POSTFIX_IFOV(c) if (unum > 1024) { unum /= 1024; postfix = c; }
  SET_POSTFIX_IFOV('K');
  SET_POSTFIX_IFOV('M');
  SET_POSTFIX_IFOV('G');
  SET_POSTFIX_IFOV('T');
  SET_POSTFIX_IFOV('P');
#undef SET_POSTFIX_IFOV

  // Print it out
  if (postfix)
    fprintf(stream, "%*" PRIuMAX "%c", width - 1, unum, postfix);
  else
    fprintf(stream, "%*" PRIuMAX, width, unum);
}

/**
 * @brief Print out info of a file in <code>ls -l</code> fashion.
 *
 * @param stream output stream
 * @param path path of file
 * @param pst pointer to stat structure of the file
 * @param link_target target of symbolic link, could be NULL
 * @param human_readable whether size should be printed in human readable
 *        format
 */
void node_print_stat_info(FILE *stream, const char *path,
    const struct stat *pst, const char *link_target, bool human_readable) {
  putc(dumpchr_stat_file_type(pst->st_mode), stream);
  dump_stat_perms(stream, pst->st_mode);
  fprintf(stream, " %d %4u %4u ", pst->st_nlink, pst->st_uid, pst->st_gid);
  if (human_readable)
    dump_sz_human(stream, pst->st_size, 5);
  else
    fprintf(stream, "%10" PRIuMAX, (uintmax_t) pst->st_size);
  putc(' ', stream);
  dump_time(stream, pst->st_mtime);
  putc(' ', stream);
  fputs(path, stream);
  if (link_target)
    fprintf(stream, " -> %s", link_target);

  // End of line
  putc('\n', stream);
}
