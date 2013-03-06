/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @file isoextract.h
 * @brief Private header of isoextract.c
 */

#include "common.h"

// === Include ===

#include <getopt.h>
#include <fnmatch.h>

#include <libisofs.h>

session_t *ps_g = NULL;

// === Types ===

/**
 * @brief Enumeration of acceptable node types.
 */
typedef enum {
  NODE_FILE,
  NODE_DIR,
} node_type_t;

/**
 * @brief Enumeration of possible match results.
 */
typedef enum {
  MATCHED_NO,
  MATCHED_DIR_PASSTHROUGH,
  MATCHED_FILE,
  MATCHED_RECURSIVE,
} matched_t;

/**
 * @brief Structure containing information iiso_callback_read() uses.
 */
struct iiso_callback_read_args {
  MirageDisc *dsk;
  MirageFragment *frag;
  long offset;
  int sector_data_len;
  int sector_padding_start;
};

/**
 * @name Helpers
 */
///@{

static inline const char *dumpstr_matched(matched_t matched) {
  switch (matched) {
    CASEMNAMERET(MATCHED_NO);
    CASEMNAMERET(MATCHED_DIR_PASSTHROUGH);
    CASEMNAMERET(MATCHED_FILE);
    CASEMNAMERET(MATCHED_RECURSIVE);
  }

  return NULL;
}

/**
 * @brief Return a const string representation of a MirageSessionTypes.
 */
static inline const char *imrg_dumpstr_sess_type(MirageSessionTypes type) {
  switch (type) {
    CASEMNAMERET(MIRAGE_SESSION_CD_ROM);
    CASEMNAMERET(MIRAGE_SESSION_CD_I);
    CASEMNAMERET(MIRAGE_SESSION_CD_ROM_XA);
  }

  return NULL;
}

/**
 * @brief Return a const string representation of a MirageTrackModes.
 */
static inline const char *imrg_dumpstr_trk_mode(MirageTrackModes mode) {
  switch (mode) {
    CASEMNAMERET(MIRAGE_MODE_MODE0);
    CASEMNAMERET(MIRAGE_MODE_AUDIO);
    CASEMNAMERET(MIRAGE_MODE_MODE1);
    CASEMNAMERET(MIRAGE_MODE_MODE2);
    CASEMNAMERET(MIRAGE_MODE_MODE2_FORM1);
    CASEMNAMERET(MIRAGE_MODE_MODE2_FORM2);
    CASEMNAMERET(MIRAGE_MODE_MODE2_MIXED);
  }

  return NULL;
}

/**
 * @brief Return a const string representation of a MirageFragment format.
 */
static inline const char *imrg_dumpstr_frag_fmt(gint format) {
  switch (format) {
    case 0: return "MIRAGE_MAIN_NULL";
    CASEMNAMERET(MIRAGE_MAIN_DATA);
    CASEMNAMERET(MIRAGE_MAIN_AUDIO);
    CASEMNAMERET(MIRAGE_MAIN_AUDIO_SWAP);
  }

  return NULL;
}

///@}

static retv_t init(session_t *ps, int argc, char **argv);

static retv_t imrg_handle_disc_abs(session_t *ps, MirageDisc *dsk);

static retv_t imrg_handle_disc_rel(session_t *ps, MirageDisc *dsk);

static bool imrg_guess_params_abs(session_t *ps, MirageDisc *dsk);

static bool imrg_guess_params_rel(session_t *ps, MirageFragment *frag,
    MirageTrackModes mode);

static IsoDataSource *imrg_build_datasrc(session_t *ps,
    MirageDisc *dsk, MirageFragment *frag);

static retv_t iiso_handle_datasrc(session_t *ps, IsoDataSource *pdatasrc);

static gchar *imrg_callback_pwd(gpointer user_data);

static matched_t node_match(session_t *ps, node_type_t node_type, 
    const char *name, const char *path, char **ptns, char ***pnewptns);

static retv_t iiso_handle_node(session_t *ps, IsoFileSource *pfile,
    char **ptns, bool force_recursive_match);

/**
 * @brief Return the stat() mode of an IsoFileSource.
 */
static inline mode_t iiso_get_file_mode(IsoFileSource *pfile) {
  struct stat st;

  if (ISO_SUCCESS != iso_file_source_stat(pfile, &st)) {
    char *path = iso_file_source_get_path(pfile);
    printf_errf("(\"%s\"): Failed to stat node.", path);
    free(path);
    return 0;
  }

  return st.st_mode;
}

/**
 * @brief Return the path of an IsoFileSource, allocated on the heap.
 */
static inline char *iiso_get_path(IsoFileSource *pfile) {
  char *path = iso_file_source_get_path(pfile);

  if (S_ISDIR(iiso_get_file_mode(pfile))) {
    int len = strlen(path);
    path = realloc(path, len + 1 + 1);
    allocchk(path);
    path[len] = '/';
    path[len + 1] = '\0';
  }

  return path;
}

static int iiso_callback_open(IsoDataSource *src);

static int iiso_callback_close(IsoDataSource *src);

static int iiso_callback_read(IsoDataSource *src, uint32_t lba, uint8_t *buffer);

static void iiso_callback_free_data(IsoDataSource *src);

static bool cfg_get(session_t *ps, int argc, char **argv);

static inline void session_destroy(session_t *ps) {
  free(ps->o.src_charset);
  free(ps->o.src_pwd);
  strv_free(&ps->o.src_paths);
  strv_free(&ps->o.tgt_ptns_wc);
#ifdef CONFIG_REGEX_PCRE
  pcrev_free(&ps->o.tgt_ptns_pcre);
  pcreexv_free(&ps->o.tgt_ptns_pcre_extra);
#endif
  free(ps->o.tgt_path);
}

static bool cfg_process_src_paths_wc(session_t *ps);

#ifdef CONFIG_REGEX_PCRE
static bool cfg_process_src_paths_pcre(session_t *ps);
#endif

static void __attribute__((noreturn)) usage(retv_t ret);
