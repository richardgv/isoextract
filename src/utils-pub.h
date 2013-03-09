/*
 * isoextract (development version)
 * https://github.com/richardgv/isoextract/
 *
 * Copyright 2013 Richard Grenville <https://github.com/richardgv>
 * License: MIT
 */

/**
 * @file utils-pub.h
 * @brief Public header of utils.c, with prototypes of public functions in
 * utils.c and shared inline utlity functions.
 */

#ifndef ISOEXT_COMMON_H
#error common.h must be included firstly!
#endif

/**
 * @name Helper functions
 */
///@{

/**
 * @brief Quit with RETV_BADALLOC if the passed-in pointer is empty.
 */
static inline void allocchk_(const char *func_name, void *ptr) {
  if (!ptr)
    printf_errq(RETV_BADALLOC, "%s(): Failed to allocate memory.", func_name);
}

/// @brief Wrapper of allocchk_().
#define allocchk(ptr) allocchk_(__func__, ptr)

#define CASEMNAMERET(s) case s: return #s

/**
 * @brief Return the smaller of two integers.
 */
static inline int min_i(int a, int b) {
  return (a > b ? b: a);
}

/**
 * @brief Return the larger of two integers.
 */
static inline int max_i(int a, int b) {
  return (a > b ? a: b);
}

/**
 * @brief Dump raw bytes in HEX format.
 *
 * @param data pointer to raw data
 * @param len length of data
 */
static inline void hexdump(const char *data, int len) {
  static const int BYTE_PER_LN = 16;

  if (len <= 0)
    return;

  // Print header
  printf("%10s:", "Offset");
  for (int i = 0; i < BYTE_PER_LN; ++i)
    printf(" %2d", i);
  putchar('\n');

  // Dump content
  for (int offset = 0; offset < len; ++offset) {
    if (!(offset % BYTE_PER_LN))
      printf("0x%08x:", offset);

    printf(" %02hhx", data[offset]);

    if ((BYTE_PER_LN - 1) == offset % BYTE_PER_LN)
      putchar('\n');
  }
  if (len % BYTE_PER_LN)
    putchar('\n');

  fflush(stdout);
}

/**
 * @brief Check if the given character is a slash.
 *
 * @todo Port to Windows / handle backslashes
 */
static inline bool isslash(char c) {
  return ('/' == c);
}

/**
 * @brief Find the first slash in a string.
 *
 * @param str source string
 *
 * @return pointer to the first slash if found, NULL otherwise
 */
static inline char *strslash(char *str) {
  return strchr(str, '/');
}

static inline bool isnstr(const char *haystick, const char *needle, unsigned len) {
  return len == strlen(needle) && !strncmp(haystick, needle, len);
}

/**
 * @brief Return the length of a string vector.
 */
static inline int strv_len(char ***pstrv) {
  return *pstrv ? (int) g_strv_length(*pstrv): 0;
}

/**
 * @brief Add a string to a string vector.
 *
 * String vectors created by other means must not be operated upon by this
 * function.
 *
 * @param pstrv target string vector
 * @param newstr pointer to an existing string to add
 */
static inline void strv_add(char ***pstrv, char *newstr) {
  static const unsigned STRLST_STEP = 3;

  if (!*pstrv) {
    *pstrv = calloc(STRLST_STEP, sizeof(char *));
    **pstrv = NULL;
  }

  unsigned len = g_strv_length(*pstrv);

  if (!((len + 1) % STRLST_STEP)) {
    *pstrv = realloc(*pstrv, (len + 1 + STRLST_STEP) * sizeof(char *));
    allocchk(*pstrv);
  }

  (*pstrv)[len] = newstr;
  (*pstrv)[len + 1] = NULL;
}

/// @brief Wrapper of strv_add() to add a copy of a string to the vector.
#define strv_add_dup(pstrv, newstr) strv_add(pstrv, g_strdup(newstr))

/*
static inline void strv_rearrange(char ***pstrv, unsigned len_orig) {
  char **start = *pstrv, **back = (*pstrv + len_orig);

  while (1) {
    while (*start && start < back)
      ++start;
    while (!(*back) && start < back)
      --back;
    if (start >= back)
      break;
    *(start++) = *(back--);
  }
} */

/**
 * @brief Free a string vector and all the strings in it.
 */
static inline void strv_free(char ***pstrv) {
  if (!*pstrv)
    return;

  for (char **strv = *pstrv; *strv; ++strv)
    free(*strv);

  free(*pstrv);
  *pstrv = NULL;
}

#ifdef CONFIG_REGEX_PCRE
/**
 * @brief Free a PCRE pattern vector and all items in it.
 */
static inline void pcrev_free(pcre ***ppcrev) {
  if (!*ppcrev)
    return;

  for (pcre **pcrev = *ppcrev; *pcrev; ++pcrev)
    pcre_free(*pcrev);

  free(*ppcrev);
  *ppcrev = NULL;
}

/**
 * @brief Free a PCRE extra data vector and all items in it.
 */
static inline void pcreexv_free(pcre_extra ***ppcreexv) {
  if (!*ppcreexv)
    return;

  for (pcre_extra **pcreexv = *ppcreexv; *pcreexv; ++pcreexv)
    LPCRE_FREE_STUDY(*pcreexv);

  free(*ppcreexv);
  *ppcreexv = NULL;
}
#endif

/**
 * @brief Destroy a reference to a GObject.
 */
static inline void free_gobj(GObject **ppgobj) {
  if (*ppgobj) {
    g_object_unref(*ppgobj);
    *ppgobj = NULL;
  }
}

/**
 * @brief Dump the error message in a GError.
 */
static inline void dump_gerror(const GError *perr) {
  printf_err("Error message: \"%s\"", perr->message);
}

bool path_create_ancestors(char *path);

void node_print_stat_info(FILE *stream, const char *path,
    const struct stat *pst, const char *link_target, bool human_readable);
