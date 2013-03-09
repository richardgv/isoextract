/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @file common.h
 * @brief Shared header of all source files, defining shared structures.
 */

#define ISOEXT_COMMON_H

// === Compile time options ===

// Whether to enable PCRE regular expression support
// #define CONFIG_REGEX_PCRE 1

// Whether to enable JIT in PCRE regular expressions
// #define CONFIG_REGEX_PCRE_JIT 1

// === Debugging options ===

// Whether to enable block read debugging
// #define DEBUG_READ 1

// === Include ===

// Require for ISSOCK(), somehow
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

#include <glib.h>
#include <mirage.h>

// libpcre
#ifdef CONFIG_REGEX_PCRE
#include <pcre.h>

// For compatiblity with <libpcre-8.20
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE    0
#define LPCRE_FREE_STUDY(extra)   pcre_free(extra)
#else
#define LPCRE_FREE_STUDY(extra)   pcre_free_study(extra)
#endif

#endif

// === Constants ===

// === Macros ===

#define MSTR_(s)        #s
#define MSTR(s)         MSTR_(s)

/// @brief Print out an error message.
#define printf_err(format, ...) \
  fprintf(stderr, format "\n", ## __VA_ARGS__)

/// @brief Print out an error message with function name.
#define printf_errf(format, ...) \
  printf_err("%s" format,  __func__, ## __VA_ARGS__)

/// @brief Print out an error message, and quit with a specific exit code.
#define printf_errq(code, format, ...) { \
  printf_err(format,  ## __VA_ARGS__); \
  exit(code); \
}

/// @brief Print out an error message with function name, and quit with a
/// specific exit code.
#define printf_errfq(code, format, ...) { \
  printf_err("%s" format,  __func__, ## __VA_ARGS__); \
  exit(code); \
}

/// @brief Print out a debug message.
#define printf_dbg(format, ...) \
  printf(format "\n", ## __VA_ARGS__); \
  fflush(stdout)

/// Print out a debug message with function name.
#define printf_dbgf(format, ...) \
  printf_dbg("%s" format, __func__, ## __VA_ARGS__)

// === Types ===

typedef struct {
  enum {
    MODE_EXTRACT,
    MODE_LIST,
  } op_mode;
  /// @brief Paths to source files.
  char **src_paths;
  /// @brief Charset of source.
  char *src_charset;
  /// @brief Password of source.
  char *src_pwd;
  /// @brief Path to extract file(s) to.
  char *tgt_path;
  /// @brief Wildcard patterns of files to extract.
  char **tgt_ptns_wc;
#ifdef CONFIG_REGEX_PCRE
  /// @brief PCRE patterns of files to extract.
  pcre **tgt_ptns_pcre;
  /// @brief Extra data for PCRE patterns of files to extract.
  pcre_extra **tgt_ptns_pcre_extra;
#endif
  /// @brief Whether to extract a matching directory recursively.
  bool recursive;
  /// @brief Level of output verbosity.
  int verbose;
  /// @brief Whether to print size in human-readable format.
  bool sz_human_readable;
  /// @brief Whether to use absolute sector positioning.
  bool abs;
  /// @brief Override sector data length, in bytes.
  int sector_data_len;
  /// @brief Override sector start padding, in bytes.
  int sector_padding_start;
  /// @brief Extra offset to be applied when reading sectors, in bytes.
  long offset;
} options_t;

#define OPTIONS_INIT { \
  .op_mode = MODE_EXTRACT, \
  .sector_data_len = -1, \
  .sector_padding_start = -1, \
}

typedef struct {
  options_t o;
  MirageContext *mrg_ctx;
  MirageDisc *mrg_dsk;
  MirageSession *mrg_sess;
  MirageTrack *mrg_trk;
  MirageFragment *mrg_frag;
  GError *mrg_err;
  int sector_data_len;
  int sector_padding_start;
} session_t;

#define SESSION_INIT { \
  .o = OPTIONS_INIT, \
}

/**
 * @brief Enumeration of possible return values.
 */
typedef enum {
  RETV_MATCHED,
  RETV_NOMATCHED,
  RETV_BADFS,
  RETV_BADIMAGE,
  RETV_INTERNAL,
  RETV_UNSUPPORTED,
  RETV_BADARG,
  RETV_BADALLOC,
  RETV_NEVER,
} retv_t;

// === Shared variables ===

extern session_t *ps_g;

// === Public headers ===

#include "isoextract-pub.h"
#include "utils-pub.h"

// === Functions ===

