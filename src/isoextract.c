/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @mainpage isoextract
 *
 * @author Richard Grenville <https://github.com/richardgv>
 *
 * isoextract is a tool that extracts files from CD-ROM images. See
 * README.asciidoc and the man page for more information.
 */

/**
 * @file isoextract.c
 * @brief Core isoextract functions.
 */

#include "isoextract.h"

#define UPD_RET(val) { \
  retv_t newret = (val); \
  if (newret < ret) \
    ret = newret; \
}

/**
 * @brief The main function.
 *
 * @param argc number of program arguments
 * @param argv array of program arguments
 *
 * @return program return value
 */
int main(int argc, char **argv) {
  // Allocate a session
  session_t *ps = malloc(sizeof(session_t));
  retv_t ret = RETV_NEVER;
  allocchk(ps);
  {
    static const session_t SESSION_DEF = SESSION_INIT;
    memcpy(ps, &SESSION_DEF, sizeof(session_t));
  }

  // Initialization
  if (RETV_NEVER != (ret = init(ps, argc, argv)))
    return ret;

  // Load image
  if (!(ps->mrg_dsk = mirage_context_load_image(ps->mrg_ctx,
          ps->o.src_paths, &ps->mrg_err))) {
    ret = RETV_BADIMAGE;
    printf_errf("(): Failed to load image.");
    dump_gerror(ps->mrg_err);
    goto main_end;
  }

  // Process image
  ret = (ps->o.abs ? imrg_handle_disc_abs(ps, ps->mrg_dsk):
      imrg_handle_disc_rel(ps, ps->mrg_dsk));

main_end:
  // Shutdown
  if (ps->mrg_dsk)
    free_gobj((GObject **) &ps->mrg_dsk);

  iso_finish();
  mirage_shutdown(&ps->mrg_err);
  session_destroy(ps);
  free(ps);

  return ret;
}

/**
 * @brief Initialize program.
 *
 * @param ps pointer to an allocated default session
 * @param argc number of program arguments
 * @param argv array of program arguments
 *
 * @return RETV_NEVER if successful, otherwise an error code
 */
static retv_t init(session_t *ps, int argc, char **argv) {
  // Read configuration
  if (!cfg_get(ps, argc, argv))
    return RETV_BADARG;

  // Initialize GType, necessary for <glib-2.36
  g_type_init();

  // Initialize libMirage
  if (!mirage_initialize(&ps->mrg_err)) {
    printf_errf("(): Failed to initialize libmirage.");
    dump_gerror(ps->mrg_err);
    return RETV_INTERNAL;
  }

  // Initialize libisofs
  if (ISO_SUCCESS != iso_init()) {
    printf_errf("(): Failed to initialize libisofs.");
    return RETV_INTERNAL;
  }

  // Create libMirage context
  if (!(ps->mrg_ctx = g_object_new(MIRAGE_TYPE_CONTEXT, NULL))) {
    printf_errf("(): Failed to create libmirage context.");
    return RETV_INTERNAL;
  }
  mirage_context_set_password_function(ps->mrg_ctx, imrg_callback_pwd, ps);

  return RETV_NEVER;
}

/**
 * @brief Process a disc using absolute positioning.
 */
static retv_t imrg_handle_disc_abs(session_t *ps, MirageDisc *dsk) {
  retv_t ret = RETV_NEVER;

  if (!imrg_guess_params_abs(ps, dsk))
    return RETV_INTERNAL;

  IsoDataSource *pdatasrc = imrg_build_datasrc(ps, ps->mrg_dsk, NULL);
  if (!pdatasrc)
    return RETV_INTERNAL;

  ret = iiso_handle_datasrc(ps, pdatasrc);
  iso_data_source_unref(pdatasrc);

  return ret;
}

/**
 * @brief Process a disc using relative positioning.
 */
static retv_t imrg_handle_disc_rel(session_t *ps, MirageDisc *dsk) {
  retv_t ret = RETV_BADIMAGE;

  // Find number of sessions
  gint nsess = 0;
  if (!(nsess = mirage_disc_get_number_of_sessions(dsk))) {
    printf_errf("(): No session found.");
    return RETV_BADIMAGE;
  }
  printf_dbgf("(): %d sessions discovered.", nsess);

  // Loop through sessions
  for (gint isess = 0; isess < nsess;
      free_gobj((GObject **) &ps->mrg_sess), ++isess) {
    if (!(ps->mrg_sess = mirage_disc_get_session_by_index(ps->mrg_dsk,
            isess, &ps->mrg_err))) {
      printf_errf("(): Failed to acquire session %d.", isess);
      dump_gerror(ps->mrg_err);
      continue;
    }

    MirageSessionTypes sess_type = mirage_session_get_session_type(ps->mrg_sess);
    printf_dbgf("(): Session %d, type %s, start %d, len %d...", isess, imrg_dumpstr_sess_type(sess_type), mirage_session_layout_get_start_sector(ps->mrg_sess), mirage_session_layout_get_length(ps->mrg_sess));
    /* if (MIRAGE_SESSION_CD_I == sess_type) {
      printf_dbgf("(): Skipping session...");
      continue;
    } */

    // Loop through tracks
    gint ntrk = mirage_session_get_number_of_tracks(ps->mrg_sess);
    printf_dbgf("(): %d tracks discovered.", ntrk);
    for (gint itrk = 0; itrk < ntrk;
        free_gobj((GObject **) &ps->mrg_trk), ++itrk) {
      if (!(ps->mrg_trk = mirage_session_get_track_by_index(ps->mrg_sess,
              itrk, &ps->mrg_err))) {
        printf_errf("(): Failed to acquire track %d.", itrk);
        dump_gerror(ps->mrg_err);
        continue;
      }

      MirageTrackModes mode = mirage_track_get_mode(ps->mrg_trk);
      printf_dbgf("(): Track %d (%d), mode %s, start_sec %d, len_sec %d...", itrk, mirage_track_layout_get_track_number(ps->mrg_trk), imrg_dumpstr_trk_mode(mode), mirage_track_layout_get_start_sector(ps->mrg_trk), mirage_track_layout_get_length(ps->mrg_trk));
      // Ignore empty tracks
      if (!mirage_track_layout_get_length(ps->mrg_trk)) {
        printf_dbgf("(): Skipping track...");
        continue;
      }

      // Loop through fragments
      gint nfrag = mirage_track_get_number_of_fragments(ps->mrg_trk);
      printf_dbgf("(): %d fragments discovered.", nfrag);
      for (gint ifrag = 0; ifrag < nfrag;
          free_gobj((GObject **) &ps->mrg_frag), ++ifrag) {
        if (!(ps->mrg_frag = mirage_track_get_fragment_by_index(ps->mrg_trk,
                ifrag, &ps->mrg_err))) {
          printf_errf("(): Failed to acquire fragment %d.", ifrag);
          dump_gerror(ps->mrg_err);
          continue;
        }

        gint frag_fmt = mirage_fragment_main_data_get_format(ps->mrg_frag);
        printf_dbgf("(): Fragment %d, fmt %s, sector_sz %d, start_sec %d, len_sec %d, main_offset %" PRIu64 "...", ifrag, imrg_dumpstr_frag_fmt(frag_fmt), mirage_fragment_main_data_get_size(ps->mrg_frag), mirage_fragment_get_address(ps->mrg_frag), mirage_fragment_get_length(ps->mrg_frag), mirage_fragment_main_data_get_offset(ps->mrg_frag));

        // Skip audio fragments and empty fragments
        if (MIRAGE_MAIN_DATA != frag_fmt
            || !mirage_fragment_get_length(ps->mrg_frag)) {
          printf_dbgf("(): Skipping fragment...");
          continue;
        }

        // Process the fragment
        IsoDataSource *pdatasrc = NULL;
        if (!imrg_guess_params_rel(ps, ps->mrg_frag, mode)) {
          UPD_RET(RETV_INTERNAL);
        }
        else if (!(pdatasrc = imrg_build_datasrc(ps, ps->mrg_dsk,
                ps->mrg_frag))) {
          UPD_RET(RETV_INTERNAL);
        }
        else {
          UPD_RET(iiso_handle_datasrc(ps, pdatasrc));
          iso_data_source_unref(pdatasrc);
        }
      }
    }
  }

  return ret;
}

/**
 * @brief Guess the data length in a sector, in bytes.
 *
 * @param ps pointer to current session
 * @param mode track mode
 * @param len full sector length
 *
 * @return true if successful, false otherwise
 */
static inline bool imrg_guess_dlen(session_t *ps, MirageTrackModes mode,
    int len) {
  // Guess the data length
  {
    int dlen = ps->o.sector_data_len;

    if (dlen <= 0) {
      switch (mode) {
        case MIRAGE_MODE_AUDIO:
          dlen = 2352;
          break;
        case MIRAGE_MODE_MODE1:
        case MIRAGE_MODE_MODE2_FORM1:
          dlen = 2048;
          break;
        case MIRAGE_MODE_MODE2:
          dlen = 2336;
          break;
        case MIRAGE_MODE_MODE2_FORM2:
          dlen = 2324;
          break;
      }
    }

    ps->sector_data_len = dlen;
  }

  // Make sure we've made a guess
  if (ps->sector_data_len <= 0) {
    printf_errf("(): Sector mode %s, failed to guess sector data length.",
        imrg_dumpstr_trk_mode(mode));
    return false;
  }

  // Sanity check
  if (ps->sector_data_len > len) {
    printf_errf("(): Sector mode %s, full sector length %d is smaller than "
        "expected data length %d.", imrg_dumpstr_trk_mode(mode),
        len, ps->sector_data_len);
    return false;
  }

  return true;
}

/**
 * @brief Guess the start padding of a sector, in bytes.
 *
 * @param ps pointer to current session
 * @param mode track mode
 * @param len full sector length
 *
 * @return true if successful, false otherwise
 */
static inline bool imrg_guess_pads(session_t *ps, MirageTrackModes mode,
    int len) {
  // Guess the start padding
  {
    const int dlen = ps->sector_data_len;

    int padding = ps->o.sector_padding_start;

    if (padding < 0) {
      if (dlen == len) {
        padding = 0;
      }
      else {
        switch (mode) {
          case MIRAGE_MODE_MODE1:
          case MIRAGE_MODE_MODE2:
            padding = 16;
            break;
          case MIRAGE_MODE_MODE2_FORM1:
          case MIRAGE_MODE_MODE2_FORM2:
            padding = 24;
            break;
        }
      }
    }

    ps->sector_padding_start = padding;
  }

  // Make sure we've made a guess
  if (ps->sector_padding_start < 0) {
    printf_errf("(): Sector mode %s, failed to guess sector start padding.",
        imrg_dumpstr_trk_mode(mode));
    return false;
  }

  // Make sure the padding is sane
  if (len < (ps->sector_data_len + ps->sector_padding_start)) {
    printf_errf("(): Sector length %d less than expected data length %d + "
        "padding %d.", len, ps->sector_data_len, ps->sector_padding_start);
    return false;
  }

  return true;
}

/**
 * @brief Guess sector parameters in absolute positioning mode.
 */
static bool imrg_guess_params_abs(session_t *ps, MirageDisc *dsk) {
  bool success = false;

  // Fetch sector 16
  MirageSector *sector = mirage_disc_get_sector(dsk, 16, &ps->mrg_err);
  if (!sector) {
    printf_errf("(): Failed to fetch sector 16.");
    goto imrg_guess_params_abs_end;
  }

  // Try fetch data from sector to get length
  gint len = 0;
  const guint8 *pbuf = NULL;
  if (!mirage_sector_get_data(sector, &pbuf, &len, &ps->mrg_err)) {
    printf_errf("(): Failed to fetch data from sector.");
    goto imrg_guess_params_abs_end;
  }

  MirageTrackModes mode = mirage_sector_get_sector_type(sector);

  if (!imrg_guess_dlen(ps, mode, len) || !imrg_guess_pads(ps, mode, len))
    goto imrg_guess_params_abs_end;

  success = true;

  printf_dbgf("(): sector_data_len %d, sector_padding_start %d",
      ps->sector_data_len, ps->sector_padding_start);

imrg_guess_params_abs_end:
  if (sector)
    free_gobj((GObject **) &sector);

  return success;
}

/**
 * @brief Guess sector parameters in relative positioning mode.
 */
static bool imrg_guess_params_rel(session_t *ps, MirageFragment *frag,
    MirageTrackModes mode) {
  const int len = mirage_fragment_main_data_get_size(frag);

  if (!imrg_guess_dlen(ps, mode, len) || !imrg_guess_pads(ps, mode, len))
    return false;

  printf_dbgf("(): sector_data_len %d, sector_padding_start %d",
      ps->sector_data_len, ps->sector_padding_start);

  return true;
}

static IsoDataSource *imrg_build_datasrc(session_t *ps,
    MirageDisc *dsk, MirageFragment *frag) {
  IsoDataSource *pdatasrc = malloc(sizeof(IsoDataSource));
  allocchk(pdatasrc);
  static const IsoDataSource ISODATASRC_DEF = {
    .version = 0,
    .refcount = 0,
    .open = iiso_callback_open,
    .close = iiso_callback_close,
    .read_block = iiso_callback_read,
    .free_data = iiso_callback_free_data,
    .data = NULL,
  };
  memcpy(pdatasrc, &ISODATASRC_DEF, sizeof(IsoDataSource));

  // Prepare read callback arguments
  struct iiso_callback_read_args *pcb_read_args =
    malloc(sizeof(struct iiso_callback_read_args));
  allocchk(pcb_read_args);
  static const struct iiso_callback_read_args CB_READ_ARGS_DEF = {
    .dsk = NULL,
    .frag = NULL,
    .offset = 0,
    .sector_data_len = 0,
    .sector_padding_start = 0,
  };
  memcpy(pcb_read_args, &CB_READ_ARGS_DEF,
      sizeof(struct iiso_callback_read_args));
  pcb_read_args->dsk = dsk;
  pcb_read_args->frag = frag;
  pcb_read_args->offset = ps->o.offset;
  pcb_read_args->sector_data_len = ps->sector_data_len;
  pcb_read_args->sector_padding_start = ps->sector_padding_start;

  pdatasrc->data = pcb_read_args;

  iso_data_source_ref(pdatasrc);

  return pdatasrc;
}

/**
 * @brief Process a disc and read the ISO9660 filesystem with an
 * IsoDataSource.
 *
 * @param ps pointer to the current session
 * @param pdatasrc IsoDataSource to read data from
 *
 * @return program return code
 */
static retv_t iiso_handle_datasrc(session_t *ps, IsoDataSource *pdatasrc) {
  retv_t ret = RETV_NOMATCHED;
  IsoReadOpts *prdopts = NULL;
  IsoImageFilesystem *pfs = NULL;

  // Build IsoReadOpts
  if (ISO_SUCCESS != iso_read_opts_new(&prdopts, 0)) {
    printf_errf("(): Failed to build IsoReadOpts.");
    ret = RETV_INTERNAL;
    goto iiso_handle_datasrc_end;
  }
  // iso_read_opts_set_default_gid(prdopts, gid);
  // iso_read_opts_set_default_permissions(prdopts, file_perm, dir_perm);
  // iso_read_opts_set_default_uid(prdopts, uid);
  if (ps->o.src_charset)
    iso_read_opts_set_input_charset(prdopts, ps->o.src_charset);
  // iso_read_opts_set_start_block(prdopts, 0);

  // Build IsoImageFilesystem
  {
    int status = iso_image_filesystem_new(pdatasrc, prdopts, 0x1fffff, &pfs);
    if (ISO_SUCCESS != status) {
      printf_errf("(): Failed to build IsoImageFilesystem: %d", status);
      ret = RETV_BADFS;
      goto iiso_handle_datasrc_end;
    }
  }
  printf_dbgf("(): IsoImageFilesystem loaded, abstract_file_id \"%s\", application_id \"%s\", biblio_file_id \"%s\", copyright_file_id \"%s\", data_preparer_id \"%s\", publisher_id \"%s\", system_id \"%s\", volset_id \"%s\", volume_id \"%s\"", iso_image_fs_get_abstract_file_id(pfs), iso_image_fs_get_application_id(pfs), iso_image_fs_get_biblio_file_id(pfs), iso_image_fs_get_copyright_file_id(pfs), iso_image_fs_get_data_preparer_id(pfs), iso_image_fs_get_publisher_id(pfs), iso_image_fs_get_system_id(pfs), iso_image_fs_get_volset_id(pfs), iso_image_fs_get_volume_id(pfs));

  // Descend into tree
  {
    IsoFileSource *root = NULL;
    if (ISO_SUCCESS != pfs->get_root(pfs, &root)) {
      printf_errf("(): Failed to get root node of the ISO filesystem.");
      goto iiso_handle_datasrc_end;
    }
    ret = iiso_handle_node(ps, root, ps->o.tgt_ptns_wc, false);
  }
  
iiso_handle_datasrc_end:
  // Cleanup
  if (pfs) {
    pfs->close(pfs);
    iso_filesystem_unref((IsoFilesystem *) pfs);
  }
  if (prdopts)
    iso_read_opts_free(prdopts);

  return ret;
}

/**
 * @brief libMirage callback to read password for an image file.
 *
 * @param user_data pointer to current session
 *
 * @return a password string allocated on the heap
 */
static gchar *imrg_callback_pwd(gpointer user_data) {
  session_t *ps = user_data;

  const char *src = ps->o.src_pwd;
  if (!src)
    src = "";

  return g_strdup(src);
}

/**
 * @brief Process a file in ISO9660 filesystem.
 *
 * @param ps pointer to current session
 * @param pfile file node
 * @param name name of the file
 * @param path full path of the file
 *
 * @return true if successful, false otherwise
 */
static inline bool iiso_handle_file(session_t *ps, IsoFileSource *pfile,
    const char *name, const char *path) {
  // Nothing more to do in list mode
  if (MODE_LIST == ps->o.op_mode)
    return true;

  bool ret = false;
  char *tpath = NULL;
  bool src_opened = false;
  FILE *fout = NULL;

  if (ISO_SUCCESS != iso_file_source_open(pfile)) {
    printf_errf("(%s): Failed to open file.", path);
    goto iiso_handle_file_end;
  }
  src_opened = true;

  // Build target path. ISO9660 filesystem path always begin with "/", so no
  // need to add one.
  tpath = g_strconcat(ps->o.tgt_path, path, NULL);

  if (!path_create_ancestors(tpath))
    goto iiso_handle_file_end;

  if(!(fout = fopen(tpath, "wb"))) {
    printf_errf("(%s): Failed to open output file \"%s\".", path, tpath);
    goto iiso_handle_file_end;
  }

  // Write the content of the file to target
  {
    static const unsigned BUF_SZ = 2048;

    char *buf[BUF_SZ];
    int len_read = 0;
    while ((len_read = iso_file_source_read(pfile, buf, BUF_SZ)) > 0) {
      if (len_read != fwrite(buf, 1, len_read, fout)) {
        printf_errf("(%s): Failed to write output file \"%s\".", path, tpath);
        break;
      }
    }

    if (len_read < 0) {
      printf_errf("(%s): Failed to read file: %d", path, len_read);
    }
    else {
      ret = true;
    }
  }

iiso_handle_file_end:
  free(tpath);
  if (src_opened)
    iso_file_source_close(pfile);
  if (fout)
    fclose(fout);

  return ret;
}

/**
 * @brief Match a segment in path against a wildcard pattern.
 *
 * @param name path segment to match
 * @param ptn wildcard pattern
 *
 * @return true if matched, false otherwise
 */
static inline bool node_match_fn(const char *name, char *ptn) {
  bool ret = false;
  char c = '\0';
  char *pc = strslash(ptn);
  if (pc) {
    c = *pc;
    *pc = '\0';
  }

  ret = !fnmatch(ptn, name, FNM_EXTMATCH);

  if (pc)
    *pc = c;

  return ret;
}

/**
 * @brief Check if a node matches.
 *
 * @param ps pointer to current session
 * @param node_type type of node
 * @param name node name
 * @param path node path
 * @param ptns wildcard patterns
 * @param pnewptns pointer to a place to store wildcard patterns to be passed
 *                 to directories/files under the node, if it's a directory
 *                 node
 *
 * @return match type
 */
static matched_t node_match(session_t *ps, node_type_t node_type, 
    const char *name, const char *path, char **ptns, char ***pnewptns) {
  matched_t matched = MATCHED_NO;
  *pnewptns = NULL;

#define UPD_MATCHED(newval) { \
  if ((newval) > matched) \
    matched = (newval); \
  if (MATCHED_RECURSIVE == matched) { \
    free(*pnewptns); \
    *pnewptns = NULL; \
    return matched; \
  } \
}

#ifdef CONFIG_REGEX_PCRE
  // With PCRE regular expressions present, let all directories pass through
  if (ps->o.tgt_ptns_pcre && NODE_DIR == node_type)
    UPD_MATCHED(MATCHED_DIR_PASSTHROUGH);

  // PCRE matching
  // PCRE matching is more costly than wildcard, so we don't match
  // directories unless recursive flag is on
  if (ps->o.tgt_ptns_pcre) {
    if ((NODE_FILE == node_type
          || (NODE_DIR == node_type && ps->o.recursive))) {
      for (int i = 0; ps->o.tgt_ptns_pcre[i]; ++i) {
        if (pcre_exec(ps->o.tgt_ptns_pcre[i], ps->o.tgt_ptns_pcre_extra[i],
              path, strlen(path), 0, 0, NULL, 0) >= 0) {
          UPD_MATCHED(NODE_DIR == node_type ? MATCHED_RECURSIVE: MATCHED_FILE);
          // No better matches possible, safe to break out here
          break;
        }
      }
    }
  }
#endif

  // Wildcard matching
  if (ptns) {
    for (char **cptn = ptns; *cptn; ++cptn) {
      char *ptn_start = *cptn;
      if (node_match_fn(name, ptn_start)) {
        char *pc = strslash(ptn_start);
        // File matching
        // Only matches with no trailing "/" is valid
        if (NODE_FILE == node_type && !pc)
          UPD_MATCHED(MATCHED_FILE);
        // Directory matching
        if (NODE_DIR == node_type) {
          // Pattern is "DIR/EXTRA..."
          if (pc && pc[1]) {
            UPD_MATCHED(MATCHED_DIR_PASSTHROUGH);
            strv_add(pnewptns, pc + 1);
          }
          // Pattern is "DIR" or "DIR/"
          else if (ps->o.recursive) {
            UPD_MATCHED(MATCHED_RECURSIVE);
          }
          else
            printf_errf("(\"%s\"): Directory omitted without -r.", path);
        }
      }
    }
  }

  return matched;
}

/**
 * @brief Display info of a ISO9660 node, if needed.
 *
 * @param ps pointer to current session
 * @param node_type node type
 * @param name node name
 * @param path node path
 * @param matched match mode
 * @param pfile IsoFileSource of node
 */
static inline void iiso_show_file(session_t *ps, node_type_t node_type,
    const char *name, const char *path, matched_t matched,
    IsoFileSource *pfile) {
  // Passthrough matches should not be considered
  if (MATCHED_DIR_PASSTHROUGH == matched)
    return;

  // Simple file path printing
  if ((MODE_LIST == ps->o.op_mode && !ps->o.verbose)
      || (MODE_EXTRACT == ps->o.op_mode && ps->o.verbose >= 1))
    printf("%s\n", path);
  // `ls -l` style
  else if (MODE_LIST == ps->o.op_mode && ps->o.verbose >= 1) {
    struct stat st;
    char *link_target = NULL;
    bool success = (ISO_SUCCESS == iso_file_source_lstat(pfile, &st));
    if (success && S_ISLNK(st.st_mode) && st.st_size) {
      link_target = calloc(st.st_size + 1, sizeof(char));
      allocchk(link_target);
      success = iso_file_source_readlink(pfile, link_target, st.st_size + 1);
    }
    if (success)
      node_print_stat_info(stdout, path, &st, link_target, ps->o.sz_human_readable);
    free(link_target);
  }
}

/**
 * @brief Process a ISO9660 node.
 *
 * @param ps current session
 * @param pfile IsoFileSource of node, guaranteed to be unref-ed
 * @param ptns wildcard patterns
 * @param force_recursive_match whether this node is already recursively
 *                              matched
 *
 * @return program return code
 */
static retv_t iiso_handle_node(session_t *ps, IsoFileSource *pfile,
    char **ptns, bool force_recursive_match) {
  char *name = NULL;
  char *path = NULL;
  retv_t ret = RETV_NOMATCHED;
  matched_t matched = MATCHED_NO;
  char **newptns = NULL;

  // Get node type
  mode_t md = iiso_get_file_mode(pfile);
  if (!(S_ISREG(md) || S_ISDIR(md))) {
    printf_errf("(%s): Unknown node type %#08x.", path, md);
    goto iiso_handle_node_end;
  }
  node_type_t node_type = (S_ISDIR(md) ? NODE_DIR: NODE_FILE);

  // Get node name/path
  name = iso_file_source_get_name(pfile);
  if (!name)
    name = g_strdup("");
  path = iiso_get_path(pfile);

  // Match
  if (force_recursive_match)
    matched = MATCHED_RECURSIVE;

  if (!matched)
    matched = node_match(ps, node_type, name, path, ptns, &newptns);

  if (!matched)
    goto iiso_handle_node_end;

  // Display file info
  iiso_show_file(ps, node_type, name, path, matched, pfile);

  // Regular file
  if (NODE_FILE == node_type) {
    if (iiso_handle_file(ps, pfile, name, path))
      ret = RETV_MATCHED;
  }
  // Directory
  else if (NODE_DIR == node_type) {
    // Open directory
    if (ISO_SUCCESS != iso_file_source_open(pfile)) {
      printf_errf("(%s): Failed to open directory.", path);
      goto iiso_handle_node_end;
    }

    // Consider it matched if recursively matched
    if (MATCHED_RECURSIVE == matched)
      ret = RETV_MATCHED;

    // Create the directory for recursive matches
    // "path" always start with "/", no need to add one
    if (MODE_EXTRACT == ps->o.op_mode && MATCHED_RECURSIVE == matched) {
      char *tpath = g_strconcat(ps->o.tgt_path, path, NULL);
      path_create_ancestors(tpath);
      free(tpath);
    }

    // Traversing through children
    IsoFileSource *child = NULL;
    while (ISO_SUCCESS == iso_file_source_readdir(pfile, &child)) {
      retv_t cret = iiso_handle_node(ps, child, newptns,
          (MATCHED_RECURSIVE == matched));
      if (cret < ret)
        ret = cret;
    }

    iso_file_source_close(pfile);
  }
  // God knows what's happening...
  else {
    assert(0);
  }

iiso_handle_node_end:
  free(newptns);
  free(path);
  free(name);
  iso_file_source_unref(pfile);

  return ret;
}

/**
 * @brief Null open callback of IsoDataSource.
 */
static int iiso_callback_open(IsoDataSource __attribute__((unused)) *src) {
  return ISO_SUCCESS;
}

/**
 * @brief Null close callback of IsoDataSource.
 */
static int iiso_callback_close(IsoDataSource __attribute__((unused)) *src) {
  return ISO_SUCCESS;
}

/**
 * @brief Read block callback of IsoDataSource to read from libMirage.
 *
 * @param src IsoDataSource
 * @param lba block number of 2048-byte blocks
 * @param buffer target buffer, 2048-byte in size
 *
 * @return ISO_SUCCESS if successful
 */
static int iiso_callback_read(IsoDataSource *src, uint32_t lba,
    uint8_t *buffer) {
  // Constants
  // The arguments isn't to be modified
  const struct iiso_callback_read_args *data = src->data;
  static const int iso_blk_len = 2048;
  const int mrg_blk_dlen = data->sector_data_len;

  // Fetch libmirage blocks one by one until the we fill 2048 bytes
  // Byte offset of next free byte in target buffer
  int offset = 0;
  // Byte offset of the start of the requested block in the libmirage element
  long req_offset = (long) iso_blk_len * lba + data->offset;
  for (int blk = req_offset / mrg_blk_dlen; offset < iso_blk_len; ++blk) {
    // Source buffer that needs to be freed later
    guint8 *pbuf = NULL;
    // Constant source buffer that shouldn't be freed
    const guint8 *cpbuf = NULL;
    // Sector object, if used
    MirageSector *sect = NULL;
    // Length of bytes read into source buffer
    gint length = 0;
    bool success = false;
    if (data->frag)
      success = mirage_fragment_read_main_data(data->frag, blk, &pbuf, &length, NULL);
    else {
      sect = mirage_disc_get_sector(data->dsk, blk, NULL);
      if (sect)
        success = mirage_sector_get_data(sect, &cpbuf, &length, NULL);
    }
    if (pbuf)
      cpbuf = pbuf;
    if (success && length < (data->sector_data_len + data->sector_padding_start)) {
      printf_errf("(): Mirage block %d (len %d) is shorter than expected data length %d + start padding %d.", blk, length, data->sector_data_len, data->sector_padding_start);
      success = false;
    }
    if (success) {
      int mrg_blk_offset = req_offset + offset - (long) mrg_blk_dlen * blk + data->sector_padding_start;
      assert(mrg_blk_offset >= data->sector_padding_start && mrg_blk_offset < data->sector_data_len + data->sector_padding_start);
      int writelen = min_i(data->sector_data_len + data->sector_padding_start - mrg_blk_offset, iso_blk_len - offset);
#ifdef DEBUG_READ
      printf_dbgf("(): ISO %6" PRIu32 ", offset %4d, MRG %6d, len %4d, offset %4d, writelen %4d", lba, offset, blk, length, mrg_blk_offset, writelen);
#endif
      memcpy(buffer + offset, cpbuf + mrg_blk_offset, writelen);
      // hexdump((const char *) cpbuf, length);
      offset += writelen;
    }
    if (pbuf)
      g_free(pbuf);
    if (sect)
      g_object_unref(sect);
    if (!success) {
      printf_errf("(): Failed to read mirage block %d.", blk);
      goto iiso_callback_read_err;
    }
  }
  // hexdump(buffer, iso_blk_len);
  assert(offset == iso_blk_len);

  return ISO_SUCCESS;

iiso_callback_read_err:
  printf_errf("(): Failed to read block %" PRIu32 ".", lba);
  return (int) ISO_DATA_SOURCE_FATAL;
}

/**
 * @brief Free data callback of IsoDataSource.
 */
static void iiso_callback_free_data(IsoDataSource *src) {
  free(src->data);
  src->data = NULL;
}

/**
 * @name Configuration handling
 *
 * Functions that handle configuration parsing/processing.
 */
///@{

/**
 * @brief Parse commandline arguments.
 *
 * @param ps pointer to current session
 * @param argc number of program arguments
 * @param argv array of program arguments
 *
 * @return true if successful, false otherwise
 */
static bool cfg_get(session_t *ps, int argc, char **argv) {
  enum {
    OPT_PASSWORD = 256,
    OPT_ABSOLUTE,
    OPT_OFFSET,
    OPT_SECTOR_DATA_LEN,
    OPT_SECTOR_PADDING_START,
    OPT_SZ_HUMAN_READABLE,
  };

  static const char * const OPTS_SHORT = "hlPrvc:i:o:";
  static const struct option OPTS_LONG[] = {
    { "help", no_argument, NULL, 'h' },
    { "password", required_argument, NULL, OPT_PASSWORD },
    { "absolute", no_argument, NULL, OPT_ABSOLUTE },
    { "offset", required_argument, NULL, OPT_OFFSET },
    { "sector-data-len", required_argument, NULL, OPT_SECTOR_DATA_LEN },
    { "sector-padding-start", required_argument, NULL, OPT_SECTOR_PADDING_START },
    { "sz-human-readable", no_argument, NULL, OPT_SZ_HUMAN_READABLE },
    { NULL, no_argument, NULL, 0 },
  };

  bool pcre = false;
  int o = -1;
  while (-1 != (o = getopt_long(argc, argv, OPTS_SHORT, OPTS_LONG, NULL))) {
    switch (o) {

#define MT_STROPT(c, tgt) case c: \
      free(ps->o.tgt); \
      ps->o.tgt = g_strdup(optarg); \
      break

      case 'h': usage(RETV_MATCHED);
      case 'l': ps->o.op_mode = MODE_LIST; break;
      case 'r': ps->o.recursive = true; break;
      case 'P': pcre = true; break;
      case OPT_SZ_HUMAN_READABLE: ps->o.sz_human_readable = true; break;
      case OPT_ABSOLUTE: ps->o.abs = true; break;
      case 'v': ++ps->o.verbose; break;
      case OPT_OFFSET: ps->o.offset = strtol(optarg, NULL, 0); break;
      case OPT_SECTOR_DATA_LEN: ps->o.sector_data_len = atoi(optarg); break;
      case OPT_SECTOR_PADDING_START: ps->o.sector_padding_start = atoi(optarg); break;
      case 'i': strv_add_dup(&ps->o.src_paths, optarg); break;
      MT_STROPT('c', src_charset);
      MT_STROPT('o', tgt_path);
      MT_STROPT(OPT_PASSWORD, src_pwd);

#undef MT_STROPT

      default:
        usage(RETV_BADARG);
    }
  }

  // Make sure we have source path
  if (!strv_len(&ps->o.src_paths)) {
    printf_errf("(): No input path found.");
    return false;
  }

  // Default target path
  if (!ps->o.tgt_path)
    ps->o.tgt_path = g_strdup(".");

  // Parse position arguments -- the target patterns
  if (argc != optind) {
    ps->o.tgt_ptns_wc = calloc(argc - optind + 1, sizeof(char *));
    allocchk(ps->o.tgt_ptns_wc);
    {
      char **p = ps->o.tgt_ptns_wc;

      while (optind < argc) {
        *(p++) = g_strdup(argv[optind++]);
      }
      *p = NULL;
    }
  }

  // Process target patterns
  bool success = false;
  if (pcre) {
#ifdef CONFIG_REGEX_PCRE
    success = cfg_process_src_paths_pcre(ps);
#else
    printf_errf("(): Program not compiled with PCRE support.");
#endif
  }
  else {
    success = cfg_process_src_paths_wc(ps);
  }

  // Append a "/" recursive matching rule if it's empty
  if (success && !ps->o.tgt_ptns_wc
#ifdef CONFIG_REGEX_PCRE
      && !ps->o.tgt_ptns_pcre
#endif
      ) {
    strv_add_dup(&ps->o.tgt_ptns_wc, "/");
    ps->o.recursive = true;
  }

  return success;
}

/**
 * @brief Process / normalize wildcard source patterns.
 */
static bool cfg_process_src_paths_wc(session_t *ps) {
  // Return if we have no patterns
  if (!ps->o.tgt_ptns_wc) {
    return true;
  }

  // Process each source pattern
  for (char **ppath = ps->o.tgt_ptns_wc; *ppath; ++ppath) {
    // Make sure the path isn't empty
    if (!((*ppath)[0])) {
      printf_errf("(): Empty source pattern is not acceptable.");
      return false;
    }

    // Postprocessing never extend path beyond one extra character
    char *newpath = malloc(strlen(*ppath) + 1 + 1);
    // Libisofs requires absolute path starting with "/"
    newpath[0] = '/';
    char *pnew = &newpath[1];
    const char *pold = ('/' == **ppath ? &(*ppath)[1]: &(*ppath)[0]);
    unsigned segm_sz = 0;
    bool pass_next = false;
    for (; *pold; ++pold) {
      // Normal character
      if ('/' != *pold) {
        if ('\\' == *pold) {
          if (pass_next)
            pass_next = false;
          // Make sure "." / "/" isn't escaped
          else if (('.' == pold[1] || '/' == pold[1]))
            continue;
          else {
            // Otherwise, let next character pass through
            pass_next = true;
          }
        }
        // For ordinary characters, just copy over
        *(pnew++) = *pold;
        ++segm_sz;
      }
      // A new segment, if the segment size isn't 0
      else if (segm_sz) {
        // "."
        if (isnstr(pnew - segm_sz, ".", segm_sz)) {
          pnew -= segm_sz + 1;
          assert('/' == *pnew);
        }
        // ".."
        else if (isnstr(pnew - segm_sz, "..", segm_sz)) {
          pnew -= segm_sz + 1;
          assert('/' == *pnew);
          *pnew = '\0';
          pnew = strrchr(newpath, '/');
          if (!pnew) {
            free(newpath);
            printf_errf("(\"%s\"): Path going beyond root node.", *ppath);
            return false;
          }
        }
        *(pnew++) = '/';
        segm_sz = 0;
      }
    }
    if (segm_sz) {
      // "."
      if (isnstr(pnew - segm_sz, ".", segm_sz)) {
        pnew -= segm_sz + 1;
        assert('/' == *pnew);
        ++pnew;
      }
      // ".."
      else if (isnstr(pnew - segm_sz, "..", segm_sz)) {
        pnew -= segm_sz + 1;
        assert('/' == *pnew);
        *pnew = '\0';
        pnew = strrchr(newpath, '/');
        if (!pnew) {
          free(newpath);
          printf_errf("(\"%s\"): Path going beyond root node.", *ppath);
          return false;
        }
        ++pnew;
      }
    }
    *pnew = '\0';

    printf_dbgf("(): \"%s\" => \"%s\"", *ppath, newpath);

    free(*ppath);
    *ppath = newpath;
  }

  return true;
}

#ifdef CONFIG_REGEX_PCRE
/**
 * @brief Process / compile PCRE source patterns.
 */
static bool cfg_process_src_paths_pcre(session_t *ps) {
  int len = strv_len(&ps->o.tgt_ptns_wc);
  if (!len)
    return true;

  // Allocate space for an array of PCRE regexps
  assert(!ps->o.tgt_ptns_pcre);
  ps->o.tgt_ptns_pcre = calloc(len + 1, sizeof(pcre *));
  allocchk(ps->o.tgt_ptns_pcre);
  ps->o.tgt_ptns_pcre_extra = calloc(len + 1, sizeof(pcre_extra *));
  allocchk(ps->o.tgt_ptns_pcre_extra);

  char ** const strv = ps->o.tgt_ptns_wc;
  pcre ** const pcrev = ps->o.tgt_ptns_pcre;
  pcrev[len] = NULL;
  pcre_extra ** const pcreexv = ps->o.tgt_ptns_pcre_extra;
  pcreexv[len] = NULL;

  // Parse from the last to the first, to avoid messing up string list
  for (int i = len - 1; i >= 0; --i) {
    const char *error = NULL;
    int erroffset = 0;
    int options = 0;

    // Compile PCRE expression
    pcrev[i] = pcre_compile(strv[i], options, &error, &erroffset, NULL);
    if (!pcrev[i]) {
      printf_errf("(%u): Pattern \"%s\": PCRE regular expression parsing "
          "failed on offset %d: %s", i, strv[i], erroffset, error);
      return false;
    }
#ifdef CONFIG_REGEX_PCRE_JIT
    pcreexv[i] = pcre_study(pcrev[i], PCRE_STUDY_JIT_COMPILE, &error);
    if (!pcreexv[i]) {
      printf_errf("(%u): Pattern \"%s\": PCRE regular expression study "
          "failed: %s", i, strv[i], error);
      return false;
    }
#else
    pcreexv[i] = NULL;
#endif

    // Free the target string
    free(strv[i]);
    strv[i] = NULL;
  }

  free(ps->o.tgt_ptns_wc);
  ps->o.tgt_ptns_wc = NULL;

  return true;
}
#endif
///@}

/**
 * @brief Print out usage text and exit with given code.
 */
static void __attribute__((noreturn)) usage(retv_t ret) {
  static const char *USAGE_STR =
    "isoextract (" ISOEXTRACT_VERSION ")\n"
    "\n"
    "Usage: isoextract -i IMAGE [-i IMAGE ...] [-o OUTPUT_PATH] [OPTIONS]\n"
    "       [PATTERN ...]\n"
    "\n"
    "Options:\n"
    "-i IMAGE\n"
    "  Specify path to an input image file. For those image formats that\n"
    "  involve multiple files, this option may be specified for multiple\n"
    "  times.\n"
    "-o OUTPUT_PATH\n"
    "  Specify output path.\n"
    "-c CHARSET\n"
    "  Specify input image charset. Run `iconv -l` to find known charsets.\n"
    "-r\n"
    "  Enable recursive directory matching. Without this option, patterns\n"
    "  cannot match a directory.\n"
#ifdef CONFIG_REGEX_PCRE
#define CONFIGFLAG_REGEX_PCRE ""
#else
#define CONFIGFLAG_REGEX_PCRE " (DISABLED AT COMPILE TIME)"
#endif
    "-P\n"
    "  Enable PCRE pattern support. This option let isoextract interpret\n"
    "  all patterns as PCRE regular expressions." CONFIGFLAG_REGEX_PCRE "\n"
#undef CONFIGFLAG_REGEX_PCRE
    "-v\n"
    "  Display verbose information. Could be used for multiple times to\n"
    "  increase verbosity.\n"
    "--password PASSWORD\n"
    "  Specify input image password, for those image formats that support\n"
    "  it.\n"
    "--absolute\n"
    "  Access sectors with absolute address, instead of relying on\n"
    "  session-track-fragment info. Needed for some broken images.\n"
    "--offset BYTES\n"
    "  Offset of the start of data, in bytes. Defaults to 0. Needed for\n"
    "  parsing nonstandard/broken images.\n"
    "--sector-data-len BYTES\n"
    "  Length of the data part in a segment. For example, 2048 for MODE-1.\n"
    "  If unspecified, isoextract tries to detect this based on\n"
    "  track/sector mode.\n"
    "--sector-padding-start BYTES\n"
    "  Length of bytes in front of a sector that should be discarded.\n"
    "  Auto-detected if not specified.\n"
    "--sz-human-readable\n"
    "  Print file size in human-readable format.\n"
    ;

  fputs(USAGE_STR, stdout);
  exit(ret);
}
