/*-*- Mode: C; c-basic-offset: 2; indent-tabs-mode: t -*-*/

/* bls.c - implementation of the boot loader spec */

/*
 *  GRUB  --  GRand Unified Bootloader
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/list.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/file.h>
#include <grub/normal.h>
#include <grub/lib/envblk.h>
#include <grub/efi/pe32.h>
#include <grub/gpt_partition.h>
#include <grub/partition.h>
#ifdef GRUB_MACHINE_EFI
#include <grub/efi/api.h>
#include <grub/efi/disk.h>
#include <grub/efi/efi.h>
#include <grub/gpt_partition.h>
#include <grub/partition.h>
#endif

#include <stdbool.h>

GRUB_MOD_LICENSE ("GPLv3+");

#include "loadenv.h"

#define GRUB_BLS_CONFIG_PATH "/loader/entries/"
#define GRUB_BLS_LINUX_PATH "/EFI/Linux"
#define PE32_HEADER_POINTER_OFFSET 0x3c
#define OSREL_SECTION_SIZE_MAX 4096
#ifdef GRUB_MACHINE_EMU
#define GRUB_BOOT_DEVICE ""
#else
#define GRUB_BOOT_DEVICE "($root)"
#endif

static const grub_gpt_part_guid_t sd_gpt_esp_guid =
  { 0xc12a7328, 0xf81f, 0x11d2,
    {0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b} };

struct keyval
{
  const char *key;
  char *val;
};

static struct bls_entry *entries = NULL;

#define FOR_BLS_ENTRIES(var) FOR_LIST_ELEMENTS (var, entries)

static int bls_add_keyval(struct bls_entry *entry, const char *key, const char *val)
{
  char *k, *v;
  struct keyval **kvs, *kv;
  int new_n = entry->nkeyvals + 1;

  kvs = grub_realloc (entry->keyvals, new_n * sizeof (struct keyval *));
  if (!kvs)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       "couldn't find space for BLS entry");
  entry->keyvals = kvs;

  kv = grub_malloc (sizeof (struct keyval));
  if (!kv)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       "couldn't find space for BLS entry");

  k = grub_strdup (key);
  if (!k)
    {
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "couldn't find space for BLS entry");
    }

  v = grub_strdup (val);
  if (!v)
    {
      grub_free (k);
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "couldn't find space for BLS entry");
    }

  kv->key = k;
  kv->val = v;

  entry->keyvals[entry->nkeyvals] = kv;
  grub_dprintf("blscfg", "new keyval at %p:%s:%s\n", entry->keyvals[entry->nkeyvals], k, v);
  entry->nkeyvals = new_n;

  return 0;
}

/* Find they value of the key named by keyname.  If there are allowed to be
 * more than one, pass a pointer to an int set to -1 the first time, and pass
 * the same pointer through each time after, and it'll return them in sorted
 * order as defined in the BLS fragment file */
static char *bls_get_val(struct bls_entry *entry, const char *keyname, int *last)
{
  int idx, start = 0;
  struct keyval *kv = NULL;

  if (last)
    start = *last + 1;

  for (idx = start; idx < entry->nkeyvals; idx++) {
    kv = entry->keyvals[idx];

    if (!grub_strcmp (keyname, kv->key))
      break;
  }

  if (idx == entry->nkeyvals) {
    if (last)
      *last = -1;
    return NULL;
  }

  if (last)
    *last = idx;

  return kv->val;
}

#define goto_return(x) ({ ret = (x); goto finish; })

/* compare alpha and numeric segments of two versions */
/* return 1: a is newer than b */
/*        0: a and b are the same version */
/*       -1: b is newer than a */
static int vercmp(const char * a, const char * b)
{
    char oldch1, oldch2;
    char *abuf, *bbuf;
    char *str1, *str2;
    char * one, * two;
    int rc;
    int isnum;
    int ret = 0;

    grub_dprintf("blscfg", "%s comparing %s and %s\n", __func__, a, b);
    if (!grub_strcmp(a, b))
	    return 0;

    abuf = grub_malloc(grub_strlen(a) + 1);
    bbuf = grub_malloc(grub_strlen(b) + 1);
    str1 = abuf;
    str2 = bbuf;
    grub_strcpy(str1, a);
    grub_strcpy(str2, b);

    one = str1;
    two = str2;

    /* loop through each version segment of str1 and str2 and compare them */
    while (*one || *two) {
	while (*one && !grub_isalnum(*one) && *one != '~' && *one != '+') one++;
	while (*two && !grub_isalnum(*two) && *two != '~' && *two != '+') two++;

	/* handle the tilde separator, it sorts before everything else */
	if (*one == '~' || *two == '~') {
	    if (*one != '~') goto_return (1);
	    if (*two != '~') goto_return (-1);
	    one++;
	    two++;
	    continue;
	}

	/*
	 * Handle plus separator. Concept is the same as tilde,
	 * except that if one of the strings ends (base version),
	 * the other is considered as higher version.
	 */
	if (*one == '+' || *two == '+') {
	    if (!*one) return -1;
	    if (!*two) return 1;
	    if (*one != '+') goto_return (1);
	    if (*two != '+') goto_return (-1);
	    one++;
	    two++;
	    continue;
	}

	/* If we ran to the end of either, we are finished with the loop */
	if (!(*one && *two)) break;

	str1 = one;
	str2 = two;

	/* grab first completely alpha or completely numeric segment */
	/* leave one and two pointing to the start of the alpha or numeric */
	/* segment and walk str1 and str2 to end of segment */
	if (grub_isdigit(*str1)) {
	    while (*str1 && grub_isdigit(*str1)) str1++;
	    while (*str2 && grub_isdigit(*str2)) str2++;
	    isnum = 1;
	} else {
	    while (*str1 && grub_isalpha(*str1)) str1++;
	    while (*str2 && grub_isalpha(*str2)) str2++;
	    isnum = 0;
	}

	/* save character at the end of the alpha or numeric segment */
	/* so that they can be restored after the comparison */
	oldch1 = *str1;
	*str1 = '\0';
	oldch2 = *str2;
	*str2 = '\0';

	/* this cannot happen, as we previously tested to make sure that */
	/* the first string has a non-null segment */
	if (one == str1) goto_return(-1);	/* arbitrary */

	/* take care of the case where the two version segments are */
	/* different types: one numeric, the other alpha (i.e. empty) */
	/* numeric segments are always newer than alpha segments */
	/* XXX See patch #60884 (and details) from bugzilla #50977. */
	if (two == str2) goto_return (isnum ? 1 : -1);

	if (isnum) {
	    grub_size_t onelen, twolen;
	    /* this used to be done by converting the digit segments */
	    /* to ints using atoi() - it's changed because long  */
	    /* digit segments can overflow an int - this should fix that. */

	    /* throw away any leading zeros - it's a number, right? */
	    while (*one == '0') one++;
	    while (*two == '0') two++;

	    /* whichever number has more digits wins */
	    onelen = grub_strlen(one);
	    twolen = grub_strlen(two);
	    if (onelen > twolen) goto_return (1);
	    if (twolen > onelen) goto_return (-1);
	}

	/* grub_strcmp will return which one is greater - even if the two */
	/* segments are alpha or if they are numeric.  don't return  */
	/* if they are equal because there might be more segments to */
	/* compare */
	rc = grub_strcmp(one, two);
	if (rc) goto_return (rc < 1 ? -1 : 1);

	/* restore character that was replaced by null above */
	*str1 = oldch1;
	one = str1;
	*str2 = oldch2;
	two = str2;
    }

    /* this catches the case where all numeric and alpha segments have */
    /* compared identically but the segment sepparating characters were */
    /* different */
    if ((!*one) && (!*two)) goto_return (0);

    /* whichever version still has characters left over wins */
    if (!*one) goto_return (-1); else goto_return (1);

finish:
    grub_free (abuf);
    grub_free (bbuf);
    return ret;
}

/* returns name/version/release */
/* NULL string pointer returned if nothing found */
static void
split_package_string (char *package_string, char **name,
                     char **version, char **release)
{
  char *package_version, *package_release;

  /* Release */
  package_release = grub_strrchr (package_string, '-');

  if (package_release != NULL)
      *package_release++ = '\0';

  *release = package_release;

  if (name == NULL)
    {
      *version = package_string;
    }
  else
    {
      /* Version */
      package_version = grub_strrchr(package_string, '-');

      if (package_version != NULL)
	*package_version++ = '\0';

      *version = package_version;
      /* Name */
      *name = package_string;
    }

  /* Bubble up non-null values from release to name */
  if (name != NULL && *name == NULL)
    {
      *name = (*version == NULL ? *release : *version);
      *version = *release;
      *release = NULL;
    }
  if (*version == NULL)
    {
      *version = *release;
      *release = NULL;
    }
}

static int
split_cmp(char *nvr0, char *nvr1, int has_name)
{
  int ret = 0;
  char *name0, *version0, *release0;
  char *name1, *version1, *release1;

  split_package_string(nvr0, has_name ? &name0 : NULL, &version0, &release0);
  split_package_string(nvr1, has_name ? &name1 : NULL, &version1, &release1);

  if (has_name)
    {
      ret = vercmp(name0 == NULL ? "" : name0,
		   name1 == NULL ? "" : name1);
      if (ret != 0)
	return ret;
    }

  ret = vercmp(version0 == NULL ? "" : version0,
	       version1 == NULL ? "" : version1);
  if (ret != 0)
    return ret;

  ret = vercmp(release0 == NULL ? "" : release0,
	       release1 == NULL ? "" : release1);
  return ret;
}

/* return 1: e0 is newer than e1 */
/*        0: e0 and e1 are the same version */
/*       -1: e1 is newer than e0 */
static int bls_cmp(const struct bls_entry *e0, const struct bls_entry *e1)
{
  char *id0, *id1;
  int r;

  id0 = grub_strdup(e0->filename);
  id1 = grub_strdup(e1->filename);

  r = split_cmp(id0, id1, 1);

  grub_free(id0);
  grub_free(id1);

  return r;
}

static void list_add_tail(struct bls_entry *head, struct bls_entry *item)
{
  item->next = head;
  if (head->prev)
    head->prev->next = item;
  item->prev = head->prev;
  head->prev = item;
}

static int bls_add_entry(struct bls_entry *entry)
{
  struct bls_entry *e, *last = NULL;
  int rc;

  if (!entries) {
    grub_dprintf ("blscfg", "Add entry with id \"%s\"\n", entry->filename);
    entries = entry;
    return 0;
  }

  FOR_BLS_ENTRIES(e) {
    rc = bls_cmp(entry, e);

    if (!rc)
      return GRUB_ERR_BAD_ARGUMENT;

    if (rc == 1) {
      grub_dprintf ("blscfg", "Add entry with id \"%s\"\n", entry->filename);
      list_add_tail (e, entry);
      if (e == entries) {
	entries = entry;
	entry->prev = NULL;
      }
      return 0;
    }
    last = e;
  }

  if (last) {
    grub_dprintf ("blscfg", "Add entry with id \"%s\"\n", entry->filename);
    last->next = entry;
    entry->prev = last;
  }

  return 0;
}

struct read_entry_info {
  const char *devid;
  const char *dirname;
  grub_file_t file;
};

static int read_entry (
    const char *filename,
    const struct grub_dirhook_info *dirhook_info UNUSED,
    void *data)
{
  grub_size_t m = 0, n, clip = 0;
  int rc = 0;
  char *p = NULL;
  grub_file_t f = NULL;
  struct bls_entry *entry;
  struct read_entry_info *info = (struct read_entry_info *)data;

  grub_dprintf ("blscfg", "filename: \"%s\"\n", filename);

  n = grub_strlen (filename);

  if (info->file)
    {
      f = info->file;
    }
  else
    {
      if (filename[0] == '.')
	return 0;

      if (n <= 5)
	return 0;

      if (grub_strcmp (filename + n - 5, ".conf") != 0)
	return 0;

      p = grub_xasprintf ("(%s)%s/%s", info->devid, info->dirname, filename);

      f = grub_file_open (p, GRUB_FILE_TYPE_CONFIG);
      if (!f)
	goto finish;
    }

  entry = grub_zalloc (sizeof (*entry));
  if (!entry)
    goto finish;

  if (info->file)
    {
      char *slash;

      if (n > 5 && !grub_strcmp (filename + n - 5, ".conf") == 0)
	clip = 5;

      slash = grub_strrchr (filename, '/');
      if (!slash)
	slash = grub_strrchr (filename, '\\');

      while (*slash == '/' || *slash == '\\')
	slash++;

      m = slash ? slash - filename : 0;
    }
  else
    {
      m = 0;
      clip = 5;
    }
  n -= m;

  entry->filename = grub_strndup(filename + m, n - clip);
  if (!entry->filename)
    goto finish;

  entry->filename[n - 5] = '\0';

  for (;;)
    {
      char *buf;
      char *separator;

      buf = grub_file_getline (f);
      if (!buf)
	break;

      while (buf && buf[0] && (buf[0] == ' ' || buf[0] == '\t'))
	buf++;
      if (buf[0] == '#')
	continue;

      separator = grub_strchr (buf, ' ');

      if (!separator)
	separator = grub_strchr (buf, '\t');

      if (!separator || separator[1] == '\0')
	{
	  grub_free (buf);
	  break;
	}

      separator[0] = '\0';

      do {
	separator++;
      } while (*separator == ' ' || *separator == '\t');

      rc = bls_add_keyval (entry, buf, separator);
      grub_free (buf);
      if (rc < 0)
	break;
    }

    if (!rc)
      bls_add_entry(entry);

finish:
  if (p)
    grub_free (p);

  if (f)
    grub_file_close (f);

  return 0;
}

static grub_err_t
get_pe32_section_header (
    grub_file_t f,
    const char *section_name,
    struct grub_pe32_section_table *section_data)
{
  grub_size_t n;
  char mz_magic[2];
  char pe_magic[4];
  grub_uint32_t pe_header_offset;
  struct grub_pe32_coff_header pe_header;
  grub_off_t sections_offset;
  int i;

  n = grub_file_read (f, mz_magic, sizeof (mz_magic));
  if (n != sizeof (mz_magic))
    return grub_errno;

  if (grub_memcmp (mz_magic, "MZ", 2) != 0)
    {
      grub_dprintf ("blscfg", "MZ header magic mismatch.\n");
      return GRUB_ERR_BAD_FILE_TYPE;
    }

  if ((grub_ssize_t) grub_file_seek (f, PE32_HEADER_POINTER_OFFSET) == -1)
    return GRUB_ERR_BAD_FILE_TYPE;

  n = grub_file_read (f, &pe_header_offset, sizeof (pe_header_offset));
  if (n != sizeof (pe_header_offset))
    return grub_errno;

  pe_header_offset = grub_le_to_cpu32 (pe_header_offset);

  if ((grub_ssize_t) grub_file_seek (f, pe_header_offset) == -1)
    return grub_errno;

  n = grub_file_read (f, &pe_magic, sizeof (pe_magic));
  if (n != sizeof (pe_magic))
    {
      grub_dprintf ("blscfg", "Error reading PE32 magic.\n");
      return grub_errno;
    }

  if (grub_memcmp (pe_magic, "PE\0\0", 4) != 0)
    {
      grub_dprintf ("blscfg", "PE32 header magic invalid.\n");
      return GRUB_ERR_BAD_FILE_TYPE;
    }

  n = grub_file_read (f, &pe_header, sizeof (pe_header));
  if (n != sizeof (pe_header))
    {
      grub_dprintf ("blscfg", "Error reading PE32 header.\n");
      return grub_errno;
    }

  pe_header.machine = grub_le_to_cpu16 (pe_header.machine);
  pe_header.num_sections = grub_le_to_cpu16 (pe_header.num_sections);
  pe_header.optional_header_size = grub_le_to_cpu16 (pe_header.optional_header_size);

  sections_offset = pe_header_offset + sizeof (pe_magic)
                    + sizeof (struct grub_pe32_coff_header)
                    + pe_header.optional_header_size;

  if ((grub_ssize_t) grub_file_seek (f, sections_offset) == -1)
    return grub_errno;

  for (i = 0; i < pe_header.num_sections; ++i)
    {
      n = grub_file_read (f, section_data, sizeof (*section_data));
      if (n != sizeof (*section_data))
  {
    grub_dprintf ("blscfg", "Error reading section headers.\n");
    return grub_errno;
  }
      if (grub_strncmp (section_data->name, section_name, sizeof (section_data->name)) == 0)
      return GRUB_ERR_NONE;
    }

    return GRUB_ERR_EOF;
}

static char*
get_value_from_osrel (const char* buffer, const char* key)
{
  const char *pos;
  const char *end;
  grub_size_t len;
  char* value;

  pos = grub_strstr (buffer, key);
  if (!pos)
    return NULL;

  pos += grub_strlen(key);

  if (*pos != '=')
      return NULL;
  ++pos;

  if (*pos == '"')
    {
      ++pos;
      end = grub_strchr (pos, '"');
    } else
      end = grub_strchr (pos, '\n');

  if (!end)
    end = pos + grub_strlen(pos);

  len = end - pos;

  value = grub_malloc (len + 1);
  if (!value)
    {
      grub_error(GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      return NULL;
    }

  grub_strncpy (value, pos, len);
  value[len] = '\0';

  return value;
}

static int
add_unified_kernel_bls_entry (const char* filename UNUSED, const char* path, const char* title)
{
  struct bls_entry *entry;
  int r;

  entry = grub_zalloc (sizeof (*entry));
  if (!entry)
    return GRUB_ERR_OUT_OF_MEMORY;

  // 0 means visible.
  entry->visible = 0;

  entry->filename = grub_strdup(path);
  if (!entry->filename)
    {
      r = GRUB_ERR_OUT_OF_MEMORY;
      goto cleanup;
    }

  r = bls_add_keyval (entry, "efi", path);
  if (r)
    goto cleanup;

  r = bls_add_keyval (entry, "title", title);
  if (r)
    goto cleanup;

  r = bls_add_entry (entry);
  if (!r)
    return GRUB_ERR_NONE;

  cleanup:
  grub_free(entry);
  return r;
}

static int
read_unified_kernel (const char *filename, const struct grub_dirhook_info *dirhook_info UNUSED,
    void *data)
{
  grub_size_t n;
  char *path = NULL;
  grub_file_t file;
  grub_err_t r;
  struct read_entry_info *info = (struct read_entry_info *)data;
  struct grub_pe32_section_table osrel_section_header;
  char *section_data = NULL;
  char *title = NULL;

  grub_dprintf ("blscfg", "efi filename: \"%s\"\n", filename);

  n = grub_strlen (filename);

  if (filename[0] == '.')
    return 0;

  if (n <= sizeof (".efi"))
    return 0;

  if (grub_strcmp (filename + n - 4, ".efi") != 0)
    return 0;

  path = grub_xasprintf ("(%s)%s/%s", info->devid, info->dirname, filename);
  if (!path)
    return 0;

  file = grub_file_open (path, GRUB_FILE_TYPE_NONE);
  if (!file)
    {
      grub_dprintf ("blscfg", "Error opening file %s", filename);
      return 0;
    }

  r = get_pe32_section_header(file, ".osrel", &osrel_section_header);
  if (r)
    {
      grub_dprintf ("blscfg", "Did not find '.osrel' section in efi file\n");
      goto finish;
    }

  if (osrel_section_header.raw_data_size > OSREL_SECTION_SIZE_MAX)
    {
      grub_dprintf (
          "blscfg",
          "'.osrel' section too large: %d",
          osrel_section_header.raw_data_size);
      goto finish;
    }

  section_data = grub_malloc (osrel_section_header.raw_data_size);
  if (!section_data)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Out of memory"));
      goto finish;
    }

  grub_file_seek (file, osrel_section_header.raw_data_offset);
  n = grub_file_read (file, section_data, osrel_section_header.raw_data_size);
  if (n != osrel_section_header.raw_data_size)
    {
      grub_dprintf ("blscfg", "Error reading section data from file\n");
      goto finish;
    }

  char *pretty_name = get_value_from_osrel (section_data, "PRETTY_NAME");
  title = grub_xasprintf ("%s [%s]", pretty_name, filename);
  if (!title)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Out of memory"));
      goto finish;
   }

  add_unified_kernel_bls_entry (filename, path, title);

  finish:
  grub_free (title);
  grub_free (section_data);
  grub_free (path);
  grub_file_close (file);

  return 0;
}

static grub_envblk_t saved_env = NULL;

static int UNUSED
save_var (const char *name, const char *value, void *whitelist UNUSED)
{
  const char *val = grub_env_get (name);
  grub_dprintf("blscfg", "saving \"%s\"\n", name);

  if (val)
    grub_envblk_set (saved_env, name, value);

  return 0;
}

static int UNUSED
unset_var (const char *name, const char *value UNUSED, void *whitelist)
{
  grub_dprintf("blscfg", "restoring \"%s\"\n", name);
  if (! whitelist)
    {
      grub_env_unset (name);
      return 0;
    }

  if (test_whitelist_membership (name,
				 (const grub_env_whitelist_t *) whitelist))
    grub_env_unset (name);

  return 0;
}

static char **bls_make_list (struct bls_entry *entry, const char *key, int *num)
{
  int last = -1;
  char *val;

  int nlist = 0;
  char **list = NULL;

  list = grub_malloc (sizeof (char *));
  if (!list)
    return NULL;
  list[0] = NULL;

  while (1)
    {
      char **new;

      val = bls_get_val (entry, key, &last);
      if (!val)
	break;

      new = grub_realloc (list, (nlist + 2) * sizeof (char *));
      if (!new)
	break;

      list = new;
      list[nlist++] = val;
      list[nlist] = NULL;
  }

  if (!nlist)
    {
      grub_free (list);
      return NULL;
    }

  if (num)
    *num = nlist;

  return list;
}

static char *field_append(bool is_var, char *buffer, const char *start, const char *end)
{
  char *tmp = grub_strndup(start, end - start + 1);
  const char *field = tmp;
  int term = is_var ? 2 : 1;

  if (is_var) {
    field = grub_env_get (tmp);
    if (!field)
      return buffer;
  }

  if (!buffer)
    buffer = grub_zalloc (grub_strlen(field) + term);
  else
    buffer = grub_realloc (buffer, grub_strlen(buffer) + grub_strlen(field) + term);

  if (!buffer)
    return NULL;

  tmp = buffer + grub_strlen(buffer);
  tmp = grub_stpcpy (tmp, field);

  if (is_var)
      tmp = grub_stpcpy (tmp, " ");

  return buffer;
}

static char *expand_val(const char *value)
{
  char *buffer = NULL;
  const char *start = value;
  const char *end = value;
  bool is_var = false;

  if (!value)
    return NULL;

  while (*value) {
    if (*value == '$') {
      if (start != end) {
	buffer = field_append(is_var, buffer, start, end);
	if (!buffer)
	  return NULL;
      }

      is_var = true;
      start = value + 1;
    } else if (is_var) {
      if (!grub_isalnum(*value) && *value != '_') {
	buffer = field_append(is_var, buffer, start, end);
	is_var = false;
	start = value;
	if (*start == ' ')
	  start++;
      }
    }

    end = value;
    value++;
  }

  if (start != end) {
    buffer = field_append(is_var, buffer, start, end);
    if (!buffer)
      return NULL;
  }

  return buffer;
}

static char **early_initrd_list (const char *initrd)
{
  int nlist = 0;
  char **list = NULL;
  char *separator;

  while ((separator = grub_strchr (initrd, ' ')))
    {
      list = grub_realloc (list, (nlist + 2) * sizeof (char *));
      if (!list)
        return NULL;

      list[nlist++] = grub_strndup(initrd, separator - initrd);
      list[nlist] = NULL;
      initrd = separator + 1;
  }

  list = grub_realloc (list, (nlist + 2) * sizeof (char *));
  if (!list)
    return NULL;

  list[nlist++] = grub_strndup(initrd, grub_strlen(initrd));
  list[nlist] = NULL;

  return list;
}

static void
create_entry_unified_kernel (struct bls_entry *entry)
{
  char *cefi;
  char *src = NULL;
  const char *argv;
  int index;
  const char *id;
  grub_err_t err;

  grub_dprintf("blscfg", "%s got here\n", __func__);
  cefi = bls_get_val (entry, "efi", NULL);
  if (!cefi)
    {
      grub_dprintf ("blscfg", "Skipping file %s with no 'efi' key.\n", entry->filename);
      return;
    }

#ifdef GRUB_MACHINE_EFI
  src = grub_xasprintf (
          "chainloader \"%s\"\n"
          "boot",
          cefi);
#else
  src = grub_xasprintf (
          "linux \"%s\"\n"
          "initrd \"%s\"\n"
          "boot",
          cefi,
          cefi);
#endif

  if (!src)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      return;
    }

  argv = bls_get_val (entry, "title", NULL);
  id = argv;

  err = grub_normal_add_menu_entry (1, &argv, NULL, id, NULL, NULL, NULL, src, 0, &index, entry);
  if (!err)
    grub_dprintf ("blscfg", "Added entry %d id:\"%s\"\n", index, id);

  grub_free (src);
}

static void create_entry_bls_config (struct bls_entry *entry)
{
  int argc = 0;
  const char **argv = NULL;

  char *title = NULL;
  char *clinux = NULL;
  char *options = NULL;
  char **initrds = NULL;
  char *initrd = NULL;
  const char *early_initrd = NULL;
  char **early_initrds = NULL;
  char *initrd_prefix = NULL;
  char *devicetree = NULL;
  char *dt = NULL;
  char *id = entry->filename;
  char *dotconf = id;
  char *hotkey = NULL;

  char *users = NULL;
  char **classes = NULL;

  char **args = NULL;

  char *src = NULL;
  int i, index;
  bool add_dt_prefix = false;

  grub_dprintf("blscfg", "%s got here\n", __func__);
  clinux = bls_get_val (entry, "linux", NULL);
  if (!clinux)
    {
      grub_dprintf ("blscfg", "Skipping file %s with no 'linux' key.\n", entry->filename);
      goto finish;
    }

  /*
   * strip the ".conf" off the end before we make it our "id" field.
   */
  do
    {
      dotconf = grub_strstr(dotconf, ".conf");
    } while (dotconf != NULL && dotconf[5] != '\0');
  if (dotconf)
    dotconf[0] = '\0';

  title = bls_get_val (entry, "title", NULL);
  options = expand_val (bls_get_val (entry, "options", NULL));

  if (!options)
    options = expand_val (grub_env_get("default_kernelopts"));

  initrds = bls_make_list (entry, "initrd", NULL);

  devicetree = expand_val (bls_get_val (entry, "devicetree", NULL));

  if (!devicetree)
    {
      devicetree = expand_val (grub_env_get("devicetree"));
      add_dt_prefix = true;
    }

  hotkey = bls_get_val (entry, "grub_hotkey", NULL);
  users = expand_val (bls_get_val (entry, "grub_users", NULL));
  classes = bls_make_list (entry, "grub_class", NULL);
  args = bls_make_list (entry, "grub_arg", &argc);

  argc += 1;
  argv = grub_malloc ((argc + 1) * sizeof (char *));
  argv[0] = title ? title : clinux;
  for (i = 1; i < argc; i++)
    argv[i] = args[i-1];
  argv[argc] = NULL;

  early_initrd = grub_env_get("early_initrd");

  grub_dprintf ("blscfg", "adding menu entry for \"%s\" with id \"%s\"\n",
		title, id);
  if (early_initrd)
    {
      early_initrds = early_initrd_list(early_initrd);
      if (!early_initrds)
      {
	grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	goto finish;
      }

      if (initrds != NULL && initrds[0] != NULL)
	{
	  initrd_prefix = grub_strrchr (initrds[0], '/');
	  initrd_prefix = grub_strndup(initrds[0], initrd_prefix - initrds[0] + 1);
	}
      else
	{
	  initrd_prefix = grub_strrchr (clinux, '/');
	  initrd_prefix = grub_strndup(clinux, initrd_prefix - clinux + 1);
	}

      if (!initrd_prefix)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	  goto finish;
	}
    }

  if (early_initrds || initrds)
    {
      int initrd_size = sizeof ("initrd");
      char *tmp;

      for (i = 0; early_initrds != NULL && early_initrds[i] != NULL; i++)
	initrd_size += sizeof (" " GRUB_BOOT_DEVICE) \
		       + grub_strlen(initrd_prefix)  \
		       + grub_strlen (early_initrds[i]) + 1;

      for (i = 0; initrds != NULL && initrds[i] != NULL; i++)
	initrd_size += sizeof (" " GRUB_BOOT_DEVICE) \
		       + grub_strlen (initrds[i]) + 1;
      initrd_size += 1;

      initrd = grub_malloc (initrd_size);
      if (!initrd)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	  goto finish;
	}

      tmp = grub_stpcpy(initrd, "initrd");
      for (i = 0; early_initrds != NULL && early_initrds[i] != NULL; i++)
	{
	  grub_dprintf ("blscfg", "adding early initrd %s\n", early_initrds[i]);
	  tmp = grub_stpcpy (tmp, " " GRUB_BOOT_DEVICE);
	  tmp = grub_stpcpy (tmp, initrd_prefix);
	  tmp = grub_stpcpy (tmp, early_initrds[i]);
	  grub_free(early_initrds[i]);
	}

      for (i = 0; initrds != NULL && initrds[i] != NULL; i++)
	{
	  grub_dprintf ("blscfg", "adding initrd %s\n", initrds[i]);
	  tmp = grub_stpcpy (tmp, " " GRUB_BOOT_DEVICE);
	  tmp = grub_stpcpy (tmp, initrds[i]);
	}
      tmp = grub_stpcpy (tmp, "\n");
    }

  if (devicetree)
    {
      char *prefix = NULL;
      int dt_size;

      if (add_dt_prefix)
	{
	  prefix = grub_strrchr (clinux, '/');
	  prefix = grub_strndup(clinux, prefix - clinux + 1);
	  if (!prefix)
	    {
	      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	      goto finish;
	    }
	}

      dt_size = sizeof("devicetree " GRUB_BOOT_DEVICE) + grub_strlen(devicetree) + 1;

      if (add_dt_prefix)
	{
	  dt_size += grub_strlen(prefix);
	}

      dt = grub_malloc (dt_size);
      if (!dt)
        {
          grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
        goto finish;
        }
      char *tmp = dt;
      tmp = grub_stpcpy (dt, "devicetree");
      tmp = grub_stpcpy (tmp, " " GRUB_BOOT_DEVICE);
      if (add_dt_prefix)
        tmp = grub_stpcpy (tmp, prefix);
      tmp = grub_stpcpy (tmp, devicetree);
      tmp = grub_stpcpy (tmp, "\n");

      grub_free(prefix);
    }

  grub_dprintf ("blscfg2", "devicetree %s for id:\"%s\"\n", dt, id);

  const char *sdval = grub_env_get("save_default");
  bool savedefault = ((NULL != sdval) && (grub_strcmp(sdval, "true") == 0));
  src = grub_xasprintf ("%sload_video\n"
			"set gfxpayload=keep\n"
			"insmod gzio\n"
			"linux %s%s%s%s\n"
			"%s%s",
			savedefault ? "savedefault\n" : "",
			GRUB_BOOT_DEVICE, clinux, options ? " " : "", options ? options : "",
			initrd ? initrd : "", dt ? dt : "");

  grub_normal_add_menu_entry (argc, argv, classes, id, users, hotkey, NULL, src, 0, &index, entry);
  grub_dprintf ("blscfg", "Added entry %d id:\"%s\"\n", index, id);

finish:
  grub_free (dt);
  grub_free (initrd);
  grub_free (initrd_prefix);
  grub_free (early_initrds);
  grub_free (devicetree);
  grub_free (initrds);
  grub_free (options);
  grub_free (classes);
  grub_free (args);
  grub_free (argv);
  grub_free (src);
}

static void create_entry (struct bls_entry *entry)
{
  char *clinux;
  char *cefi;

  grub_dprintf("blscfg", "%s got here\n", __func__);

  clinux = bls_get_val (entry, "linux", NULL);
  cefi = bls_get_val (entry, "efi", NULL);

  if (clinux && cefi)
    {
      grub_dprintf (
          "blscfg",
          "Error: Got both 'linux' and 'efi' fields in the same entry %s\n",
          entry->filename);
    }
  else if (clinux)
    {
      create_entry_bls_config (entry);
    }
  else
  {
    create_entry_unified_kernel (entry);
  }

}

struct find_entry_info {
	const char *dirname;
	const char *devid;
	grub_device_t dev;
	grub_fs_t fs;
};

/*
 * info: the filesystem object the file is on.
 */
static int find_unified_kernels (const struct find_entry_info *info)
{
  struct read_entry_info read_entry_info;
  grub_fs_t blsdir_fs = NULL;
  grub_device_t blsdir_dev = NULL;
  const char *blsdir = info->dirname;
  int r = 0;

  if (!blsdir)
    {
      blsdir = grub_env_get ("blslinuxdir");
      if (!blsdir)
  blsdir = GRUB_BLS_LINUX_PATH;
    }

  read_entry_info.file = NULL;
  read_entry_info.dirname = blsdir;

  grub_dprintf ("blscfg", "scanning blslinuxdir: %s\n", blsdir);

  blsdir_dev = info->dev;
  blsdir_fs = info->fs;
  read_entry_info.devid = info->devid;

  r = blsdir_fs->fs_dir (
        blsdir_dev,
        read_entry_info.dirname,
        read_unified_kernel,
        &read_entry_info);
  if (r != 0)
    {
      grub_dprintf ("blscfg", "read_unified_kernel returned error\n");
      grub_err_t e;
      do
  {
    e = grub_error_pop();
  } while (e);
    }

  return 0;
}

/*
 * info: the filesystem object the file is on.
 */
static int find_entry (struct find_entry_info *info)
{
  struct read_entry_info read_entry_info;
  grub_fs_t blsdir_fs = NULL;
  grub_device_t blsdir_dev = NULL;
  const char *blsdir = info->dirname;
  int fallback = 0;
  int r = 0;

  if (!blsdir) {
    blsdir = grub_env_get ("blsdir");
    if (!blsdir)
      blsdir = GRUB_BLS_CONFIG_PATH;
  }

  read_entry_info.file = NULL;
  read_entry_info.dirname = blsdir;

  grub_dprintf ("blscfg", "scanning blsdir: %s\n", blsdir);

  blsdir_dev = info->dev;
  blsdir_fs = info->fs;
  read_entry_info.devid = info->devid;

read_fallback:
  r = blsdir_fs->fs_dir (blsdir_dev, read_entry_info.dirname, read_entry,
			 &read_entry_info);
  if (r != 0) {
      grub_dprintf ("blscfg", "read_entry returned error\n");
      grub_err_t e;
      do
	{
	  e = grub_error_pop();
	} while (e);
  }

  if (r && !info->dirname && !fallback) {
    read_entry_info.dirname = "/boot" GRUB_BLS_CONFIG_PATH;
    grub_dprintf ("blscfg", "Entries weren't found in %s, fallback to %s\n",
		  blsdir, read_entry_info.dirname);
    fallback = 1;
    goto read_fallback;
  }

  return 0;
}

static grub_err_t
scan_device (const char* devid)
{
  grub_err_t r = GRUB_ERR_NONE;

  struct find_entry_info info = {
      .dev = NULL,
      .fs = NULL,
      .dirname = NULL,
  };

  grub_dprintf ("blscfg", "opening %s\n", devid);
  info.dev = grub_device_open (devid);
  if (!info.dev)
    return grub_errno;

  grub_dprintf ("blscfg", "probing fs\n");
  info.fs = grub_fs_probe (info.dev);
  if (!info.fs)
    {
      r = grub_errno;
      goto finish;
    }

  info.devid = devid;
  find_entry (&info);
  find_unified_kernels (&info);

finish:
  if (info.dev)
    grub_device_close (info.dev);

  return r;
}

static int compare_gpt_guid (const grub_gpt_part_guid_t *a, const grub_gpt_part_guid_t *b)
{
  return grub_memcmp (a, b, sizeof (grub_gpt_part_guid_t));
}

static void
print_guid (const char *text, const struct grub_gpt_part_guid *guid)
{
    grub_dprintf ("blscfg", "%s"
       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x \n",
       text,
       grub_le_to_cpu32 (guid->data1),
       grub_le_to_cpu16 (guid->data2),
       grub_le_to_cpu16 (guid->data3),
       guid->data4[0], guid->data4[1], guid->data4[2],
       guid->data4[3], guid->data4[4], guid->data4[5],
       guid->data4[6], guid->data4[7]);
}


static int
part_hook_esp (struct grub_disk *disk , const grub_partition_t part,
           void *data)
{
  struct grub_gpt_partentry entry;

  if (!data)
    return 2;

  grub_dprintf ("blscfg",
                "PART: index = %d number = %d offset = 0x%llx len = %lld\n",
                part->index, part->number, part->offset, part->len);


  if (grub_disk_read (
        disk,
        part->offset,
        part->index,
        sizeof (entry),
        &entry))
    {
      grub_dprintf ("blscfg", "%s: Read error\n", disk->name);
    }

  if (compare_gpt_guid (&entry.type, &sd_gpt_esp_guid) == 0)
  {
    print_guid ("Found ESP UUID = ", &entry.guid);
    grub_dprintf ("blscfg", "-> %s,gpt%d\n", disk->name, part->number);

    int *out = (int *) data;
    *out = part->number;
    return 1;
  }
  return 0;
}

#ifdef GRUB_MACHINE_EFI
static char *
machine_get_bootdevice (void)
{
  grub_efi_loaded_image_t *image;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (!image)
    return NULL;

  return grub_efidisk_get_device_name (image->device_handle);
}
#endif

static grub_err_t
machine_get_bootlocation_bios (char **esp)
{

  const char *device_name;
  grub_device_t dev;
  grub_disk_t disk = NULL;
  grub_err_t status = GRUB_ERR_OUT_OF_RANGE;
  int part_number = -1;

  device_name = grub_env_get ("root");
  if (!device_name)
    {
      grub_dprintf ("blscfg", "root not set\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_dprintf ("blscfg", "root = %s\n", device_name);

  dev = grub_device_open (device_name);
  if (!dev)
    {
      grub_dprintf ("blscfg", "Error opening device %s\n", device_name);
      goto finish;
    }

  if (!dev->disk || !dev->disk->partition)
    {
      grub_dprintf ("blscfg", "Not a disk or not a partiton\n"); // TODO
      goto finish;
    }

  disk = grub_disk_open (dev->disk->name);
  if (!disk)
    {
      grub_dprintf ("blscfg", "Error opening disk\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  if (grub_strcmp (dev->disk->partition->partmap->name, "gpt") != 0)
    {
      grub_dprintf ("blscfg", "%s: Not a gpt patition table\n",
                    dev->disk->name);
      goto finish;
    }

  if (1 == grub_partition_iterate (disk, part_hook_esp, &part_number))
  {
     *esp = grub_xasprintf ("%s,gpt%d", disk->name, part_number + 1);
     status = GRUB_ERR_NONE;
  }

finish:

  if (disk)
    grub_disk_close (disk);

  if (dev)
    grub_device_close (dev);

  return status;
}

static grub_err_t
bls_load_entries (void)
{
  const char* boot = NULL;
  char *esp = NULL;

#ifdef GRUB_MACHINE_EMU
  boot = "host";
#else
  boot = grub_env_get ("root");
#endif

#ifdef GRUB_MACHINE_EFI
  esp = machine_get_bootdevice ();
#else
  machine_get_bootlocation_bios (&esp);
#endif

  if (esp)
  {
    grub_dprintf ("blscfg", "Scanning ESP: %s\n", esp);
    scan_device (esp);
  } else {
    grub_dprintf ("blscfg", "ESP not found.\n");
  }

  if (boot)
  {
    if (grub_strcmp (boot, esp) == 0)
      {
        grub_dprintf("blscfg", "$root points to ESP, skipping.\n");
      } else {
        grub_dprintf ("blscfg", "Scanning BOOT: %s\n", boot);
        scan_device (boot);
      }
  } else {
    grub_dprintf ("blscfg", "BOOT not found. Maybe $root not set?\n");
  }

  grub_free (esp);

  return GRUB_ERR_NONE;
}

static bool
is_default_entry(const char *def_entry, struct bls_entry *entry, int idx)
{
  const char *title;
  int def_idx;

  if (!def_entry)
    return false;

  if (grub_strcmp(def_entry, entry->filename) == 0)
    return true;

  title = bls_get_val(entry, "title", NULL);

  if (title && grub_strcmp(def_entry, title) == 0)
    return true;

  def_idx = (int)grub_strtol(def_entry, NULL, 0);
  if (grub_errno == GRUB_ERR_BAD_NUMBER) {
    grub_errno = GRUB_ERR_NONE;
    return false;
  }

  if (def_idx == idx)
    return true;

  return false;
}

static grub_err_t
bls_create_entries (bool show_default, bool show_non_default, char *entry_id)
{
  const char *def_entry = NULL;
  struct bls_entry *entry = NULL;
  int idx = 0;

  def_entry = grub_env_get("default");

  grub_dprintf ("blscfg", "%s Creating entries from bls\n", __func__);
  FOR_BLS_ENTRIES(entry) {
    if (entry->visible) {
      idx++;
      continue;
    }

    if ((show_default && is_default_entry(def_entry, entry, idx)) ||
	(show_non_default && !is_default_entry(def_entry, entry, idx)) ||
	(entry_id && grub_strcmp(entry_id, entry->filename) == 0)) {
      create_entry(entry);
      entry->visible = 1;
    }
    idx++;
  }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_blscfg (grub_extcmd_context_t ctxt UNUSED,
		 int argc, char **args)
{
  grub_err_t r;
  char *entry_id = NULL;
  bool show_default = true;
  bool show_non_default = true;

  if (argc == 1) {
    if (grub_strcmp (args[0], "default") == 0) {
      show_non_default = false;
    } else if (grub_strcmp (args[0], "non-default") == 0) {
      show_default = false;
    } else {
      entry_id = args[0];
      show_default = false;
      show_non_default = false;
    }
  }

  r = bls_load_entries ();
  if (r)
    return r;

  return bls_create_entries(show_default, show_non_default, entry_id);
}

static grub_extcmd_t cmd;
static grub_extcmd_t oldcmd;

GRUB_MOD_INIT(blscfg)
{
  grub_dprintf("blscfg", "%s got here\n", __func__);
  cmd = grub_register_extcmd ("blscfg",
			      grub_cmd_blscfg,
			      0,
			      NULL,
			      N_("Import Boot Loader Specification snippets."),
			      NULL);
  oldcmd = grub_register_extcmd ("bls_import",
				 grub_cmd_blscfg,
				 0,
				 NULL,
				 N_("Import Boot Loader Specification snippets."),
				 NULL);
}

GRUB_MOD_FINI(blscfg)
{
  grub_unregister_extcmd (cmd);
  grub_unregister_extcmd (oldcmd);
}
