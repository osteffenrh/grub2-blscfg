/* linux.c - boot Linux zImage or bzImage */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/loader.h>
#include <grub/file.h>
#include <grub/err.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/memory.h>
#include <grub/dl.h>
#include <grub/cpu/linux.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/mm.h>
#include <grub/cpu/relocator.h>
#include <grub/video.h>
#include <grub/i386/floppy.h>
#include <grub/lib/cmdline.h>
#include <grub/linux.h>
#include <grub/safemath.h>
#include <grub/efi/sb.h>
#include <grub/gpt_partition.h>
#include <grub/partition.h>

#include <grub/efi/pe32.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_LINUX_CL_OFFSET		0x9000

static grub_dl_t my_mod;

static grub_size_t linux_mem_size;
static int loaded;
static struct grub_relocator *relocator = NULL;
static grub_addr_t grub_linux_real_target;
static char *grub_linux_real_chunk;
static grub_size_t grub_linux16_prot_size;
static grub_size_t maximal_cmdline_size;

static grub_err_t
grub_linux16_boot (void)
{
  grub_uint16_t segment;
  struct grub_relocator16_state state;

  segment = grub_linux_real_target >> 4;
  state.gs = state.fs = state.es = state.ds = state.ss = segment;
  state.sp = GRUB_LINUX_SETUP_STACK;
  state.cs = segment + 0x20;
  state.ip = 0;
  state.a20 = 1;

  grub_video_set_mode ("text", 0, 0);

  grub_stop_floppy ();
  
  return grub_relocator16_boot (relocator, state);
}

static grub_err_t
grub_linux_unload (void)
{
  grub_dl_unref (my_mod);
  loaded = 0;
  grub_relocator_unload (relocator);
  relocator = NULL;
  return GRUB_ERR_NONE;
}

static int
target_hook (grub_uint64_t addr, grub_uint64_t size, grub_memory_type_t type,
	    void *data)
{
  grub_uint64_t *result = data;
  grub_uint64_t candidate;

  if (type != GRUB_MEMORY_AVAILABLE)
    return 0;
  if (addr >= 0xa0000)
    return 0;
  if (addr + size >= 0xa0000)
    size = 0xa0000 - addr;

  /* Put the real mode part at as a high location as possible.  */
  candidate = addr + size - (GRUB_LINUX_CL_OFFSET + maximal_cmdline_size);
  /* But it must not exceed the traditional area.  */
  if (candidate > GRUB_LINUX_OLD_REAL_MODE_ADDR)
    candidate = GRUB_LINUX_OLD_REAL_MODE_ADDR;
  if (candidate < addr)
    return 0;

  if (candidate > *result || *result == (grub_uint64_t) -1)
    *result = candidate;
  return 0;
}

static grub_addr_t
grub_find_real_target (void)
{
  grub_uint64_t result = (grub_uint64_t) -1;

  grub_mmap_iterate (target_hook, &result);
  return result;
}

#define MODNAME "blscfg"

static const grub_gpt_part_guid_t sd_gpt_root_x86_64_guid =
  { 0x4f68bce3, 0xe8cd, 0x4db1,
    {0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09} };

static int compare_gpt_guid (const grub_gpt_part_guid_t *a, const grub_gpt_part_guid_t *b)
{
  return grub_memcmp (a, b, sizeof (grub_gpt_part_guid_t));
}

static void
print_guid (const char *text, const struct grub_gpt_part_guid *guid)
{
    grub_dprintf (MODNAME, "%s"
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
part_hook_root (struct grub_disk *disk , const grub_partition_t part,
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

  if (compare_gpt_guid (&entry.type, &sd_gpt_root_x86_64_guid) == 0)
  {
    grub_dprintf ("blscfg", "-> %s,gpt%d\n", disk->name, part->number);

    print_guid ("UUID=", &(entry.guid));

    grub_memcpy (data, &(entry.guid), sizeof (grub_gpt_part_guid_t));

    return 1;
  }
  return 0;
}

static grub_err_t
find_root_part_uuid (char **uuid)
{

  const char *device_name;
  grub_device_t dev;
  grub_disk_t disk = NULL;
  grub_err_t status = GRUB_ERR_OUT_OF_RANGE;
  grub_gpt_part_guid_t guid = {};

  device_name = grub_env_get ("root");
  if (!device_name)
    {
      grub_dprintf (MODNAME, "root not set\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_dprintf (MODNAME, "root = %s\n", device_name);

  dev = grub_device_open (device_name);
  if (!dev)
    {
      grub_dprintf (MODNAME, "Error opening device %s\n", device_name);
      goto finish;
    }

  if (!dev->disk || !dev->disk->partition)
    {
      grub_dprintf (MODNAME, "Not a disk or not a partiton\n"); // TODO
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

  if (1 == grub_partition_iterate (disk, part_hook_root, &guid))
  {
     *uuid = grub_xasprintf (
       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
       grub_le_to_cpu32 (guid.data1),
       grub_le_to_cpu16 (guid.data2),
       grub_le_to_cpu16 (guid.data3),
       guid.data4[0], guid.data4[1], guid.data4[2],
       guid.data4[3], guid.data4[4], guid.data4[5],
       guid.data4[6], guid.data4[7]);

     status = GRUB_ERR_NONE;
  }

finish:

  if (disk)
    grub_disk_close (disk);

  if (dev)
    grub_device_close (dev);

  return status;
}
#define PE32_HEADER_POINTER_OFFSET 0x3c
#define OSREL_SECTION_SIZE_MAX 4096

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

static grub_err_t
prepare_linux (grub_uint8_t* kernel, grub_ssize_t len, int argc, char *argv[])
{
  struct linux_i386_kernel_header lh;
  grub_uint8_t setup_sects;
  grub_size_t real_size, kernel_offset = 0;
  int i;
  char *grub_linux_prot_chunk;
  int grub_linux_is_bzimage;
  grub_addr_t grub_linux_prot_target;
  grub_err_t err;
  grub_memcpy (&lh, kernel, sizeof (lh));
  kernel_offset = sizeof (lh);

  if (lh.boot_flag != grub_cpu_to_le16_compile_time (0xaa55))
    {
      grub_error (GRUB_ERR_BAD_OS, "invalid magic number");
      goto fail;
    }

  if (lh.setup_sects > GRUB_LINUX_MAX_SETUP_SECTS)
    {
      grub_error (GRUB_ERR_BAD_OS, "too many setup sectors");
      goto fail;
    }

  grub_linux_is_bzimage = 0;
  setup_sects = lh.setup_sects;
  linux_mem_size = 0;

  maximal_cmdline_size = 256;

  if (lh.header == grub_cpu_to_le32_compile_time (GRUB_LINUX_I386_MAGIC_SIGNATURE)
      && grub_le_to_cpu16 (lh.version) >= 0x0200)
    {
      grub_linux_is_bzimage = (lh.loadflags & GRUB_LINUX_FLAG_BIG_KERNEL);
      lh.type_of_loader = GRUB_LINUX_BOOT_LOADER_TYPE;

      if (grub_le_to_cpu16 (lh.version) >= 0x0206)
	maximal_cmdline_size = grub_le_to_cpu32 (lh.cmdline_size) + 1;

      grub_linux_real_target = grub_find_real_target ();
      if (grub_linux_real_target == (grub_addr_t)-1)
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE,
		      "no appropriate low memory found");
	  goto fail;
	}

      if (grub_le_to_cpu16 (lh.version) >= 0x0201)
	{
	  lh.heap_end_ptr = grub_cpu_to_le16_compile_time (GRUB_LINUX_HEAP_END_OFFSET);
	  lh.loadflags |= GRUB_LINUX_FLAG_CAN_USE_HEAP;
	}

      if (grub_le_to_cpu16 (lh.version) >= 0x0202)
	lh.cmd_line_ptr = grub_linux_real_target + GRUB_LINUX_CL_OFFSET;
      else
	{
	  lh.cl_magic = grub_cpu_to_le16_compile_time (GRUB_LINUX_CL_MAGIC);
	  lh.cl_offset = grub_cpu_to_le16_compile_time (GRUB_LINUX_CL_OFFSET);
	  lh.setup_move_size = grub_cpu_to_le16_compile_time (GRUB_LINUX_CL_OFFSET
						 + maximal_cmdline_size);
	}
    }
  else
    {
      /* Your kernel is quite old...  */
      lh.cl_magic = grub_cpu_to_le16_compile_time (GRUB_LINUX_CL_MAGIC);
      lh.cl_offset = grub_cpu_to_le16_compile_time (GRUB_LINUX_CL_OFFSET);

      setup_sects = GRUB_LINUX_DEFAULT_SETUP_SECTS;

      grub_linux_real_target = GRUB_LINUX_OLD_REAL_MODE_ADDR;
    }

  /* If SETUP_SECTS is not set, set it to the default (4).  */
  if (! setup_sects)
    setup_sects = GRUB_LINUX_DEFAULT_SETUP_SECTS;

  real_size = setup_sects << GRUB_DISK_SECTOR_BITS;
  if (grub_sub (len, real_size, &grub_linux16_prot_size) ||
      grub_sub (grub_linux16_prot_size, GRUB_DISK_SECTOR_SIZE, &grub_linux16_prot_size))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
      goto fail;
    }

  if (! grub_linux_is_bzimage
      && GRUB_LINUX_ZIMAGE_ADDR + grub_linux16_prot_size
      > grub_linux_real_target)
    {
      grub_error (GRUB_ERR_BAD_OS, "too big zImage (0x%" PRIxGRUB_SIZE
		  " > 0x%" PRIxGRUB_ADDR "), use bzImage instead",
		  GRUB_LINUX_ZIMAGE_ADDR + grub_linux16_prot_size,
		  grub_linux_real_target);
      goto fail;
    }

  grub_dprintf ("linux", "[Linux-%s, setup=0x%x, size=0x%x]\n",
		grub_linux_is_bzimage ? "bzImage" : "zImage",
		(unsigned) real_size,
		(unsigned) grub_linux16_prot_size);

  for (i = 1; i < argc; i++)
    if (grub_memcmp (argv[i], "vga=", 4) == 0)
      {
	/* Video mode selection support.  */
	grub_uint16_t vid_mode;
	char *val = argv[i] + 4;

	if (grub_strcmp (val, "normal") == 0)
	  vid_mode = GRUB_LINUX_VID_MODE_NORMAL;
	else if (grub_strcmp (val, "ext") == 0)
	  vid_mode = GRUB_LINUX_VID_MODE_EXTENDED;
	else if (grub_strcmp (val, "ask") == 0)
	  vid_mode = GRUB_LINUX_VID_MODE_ASK;
	else
	  vid_mode = (grub_uint16_t) grub_strtoul (val, 0, 0);

	if (grub_errno)
	  goto fail;

	lh.vid_mode = grub_cpu_to_le16 (vid_mode);
      }
    else if (grub_memcmp (argv[i], "mem=", 4) == 0)
      {
	const char *val = argv[i] + 4;

	linux_mem_size = grub_strtoul (val, &val, 0);

	if (grub_errno)
	  {
	    grub_errno = GRUB_ERR_NONE;
	    linux_mem_size = 0;
	  }
	else
	  {
	    int shift = 0;

	    switch (grub_tolower (val[0]))
	      {
	      case 'g':
		shift += 10;
		/* Fallthrough.  */
	      case 'm':
		shift += 10;
		/* Fallthrough.  */
	      case 'k':
		shift += 10;
		/* Fallthrough.  */
	      default:
		break;
	      }

	    /* Check an overflow.  */
	    if (linux_mem_size > (~0UL >> shift))
	      linux_mem_size = 0;
	    else
	      linux_mem_size <<= shift;
	  }
      }

  relocator = grub_relocator_new ();
  if (!relocator)
    goto fail;

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   grub_linux_real_target,
					   GRUB_LINUX_CL_OFFSET
					   + maximal_cmdline_size);
    if (err)
      return err;
    grub_linux_real_chunk = get_virtual_current_address (ch);
  }

  /* Put the real mode code at the temporary address.  */
  grub_memmove (grub_linux_real_chunk, &lh, sizeof (lh));

  len = real_size + GRUB_DISK_SECTOR_SIZE - sizeof (lh);
  grub_memcpy (grub_linux_real_chunk + sizeof (lh), kernel + kernel_offset,
	       len);
  kernel_offset += len;

  if (lh.header != grub_cpu_to_le32_compile_time (GRUB_LINUX_I386_MAGIC_SIGNATURE)
      || grub_le_to_cpu16 (lh.version) < 0x0200)
    /* Clear the heap space.  */
    grub_memset (grub_linux_real_chunk
		 + ((setup_sects + 1) << GRUB_DISK_SECTOR_BITS),
		 0,
		 ((GRUB_LINUX_MAX_SETUP_SECTS - setup_sects - 1)
		  << GRUB_DISK_SECTOR_BITS));

  /* Create kernel command line.  */
  grub_memcpy ((char *)grub_linux_real_chunk + GRUB_LINUX_CL_OFFSET,
		LINUX_IMAGE, sizeof (LINUX_IMAGE));
  err = grub_create_loader_cmdline (argc, argv,
				    (char *)grub_linux_real_chunk
				    + GRUB_LINUX_CL_OFFSET + sizeof (LINUX_IMAGE) - 1,
				    maximal_cmdline_size
				    - (sizeof (LINUX_IMAGE) - 1),
				    GRUB_VERIFY_KERNEL_CMDLINE);
  if (err)
    goto fail;

  if (grub_linux_is_bzimage)
    grub_linux_prot_target = GRUB_LINUX_BZIMAGE_ADDR;
  else
    grub_linux_prot_target = GRUB_LINUX_ZIMAGE_ADDR;
  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   grub_linux_prot_target,
					   grub_linux16_prot_size);
    if (err)
      return err;
    grub_linux_prot_chunk = get_virtual_current_address (ch);
  }

  len = grub_linux16_prot_size;
  grub_memcpy (grub_linux_prot_chunk, kernel + kernel_offset, len);
  kernel_offset += len;

  if (grub_errno == GRUB_ERR_NONE)
    {
      grub_loader_set (grub_linux16_boot, grub_linux_unload, 0);
      loaded = 1;
    }

 fail:

  // grub_free (kernel); // up

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0; // up
      grub_relocator_unload (relocator);
    }

  return grub_errno;
}

static grub_err_t
chop_cmdline (char* cmdline, int *argc, char ***argv, int extra_args)
{
  *argc = 1;
  for (const char *p = cmdline; *p != '\0'; ++p)
    if (*p == ' ')
      ++(*argc);

  grub_dprintf("linux", "cmdline: found %d args\n", *argc);
  *argc += extra_args;
  *argv = grub_calloc(*argc, sizeof (char *));
  if (!(*argv))
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Out of memory"));

  char **c = (*argv) + 1;
  for (char *p = cmdline; *p != '\0'; ++p)
    if (*p == ' ') {
      *p = '\0';
      *(c++) = (p+1);
    }

  return GRUB_ERR_NONE;
}


static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  grub_ssize_t len;
  grub_uint8_t *kernel = NULL;
  grub_err_t status;
  struct grub_pe32_section_table section_header;
  struct grub_pe32_section_table cmdline_section_header;
  int cmdline_argc = 0;
  char **cmdline_argv = NULL;
  char **local_cmdline_argv = NULL;
  char *uki_cmdline_data = NULL;
  char *extra_root = NULL;

  grub_dl_ref (my_mod);

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      return grub_errno;
    }

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_LINUX_KERNEL);
  if (! file)
    return grub_errno;

  status = get_pe32_section_header(file, ".linux", &section_header);
  if (status != GRUB_ERR_NONE)
    {
      grub_dprintf("linux", "Not a UKI: %s\n", argv[0]);
      len = grub_file_size (file);
      grub_file_seek (file, 0);
      cmdline_argc = argc;
      cmdline_argv = argv;
    }
  else
    { // This is a uki
      grub_dprintf("linux", "UKI identified: %s. Loading image from .linux section.\n", argv[0]);

      grub_file_seek (file, 0);

      status = get_pe32_section_header (file, ".cmdline", &cmdline_section_header);
      if (status != GRUB_ERR_NONE)
        {
          grub_dprintf ("linux", "No command line section present in UKI\n");
          cmdline_argc = argc;
          cmdline_argv = argv;
        } else {
          grub_dprintf ("linux", ".cmdline off=0x%x, size=0x%x\n", cmdline_section_header.raw_data_offset, cmdline_section_header.raw_data_size);

          grub_file_seek (file, cmdline_section_header.raw_data_offset);
         // if (status != GRUB_ERR_NONE)
          //  return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("SEEK failed")); // TODO?

          uki_cmdline_data = grub_calloc (cmdline_section_header.raw_data_size, sizeof (char));
          if (!uki_cmdline_data)
            return grub_errno;

          grub_ssize_t s;
          s = grub_file_read (file, uki_cmdline_data, cmdline_section_header.raw_data_size);
          if (s != (grub_ssize_t) cmdline_section_header.raw_data_size)
          {
            grub_dprintf ("linux", "read %d, expected %d\n", s, cmdline_section_header.raw_data_size);
            return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("File too short while reading section")); // TODO?
          }
          if (grub_strstr (uki_cmdline_data, "root=") == NULL)
          {
              grub_dprintf (MODNAME, "cmdline does not contain root=... scanning for partition...\n");
              char *uuid = NULL;
              if (find_root_part_uuid (&uuid) == GRUB_ERR_NONE)
              {
                grub_dprintf (MODNAME, "root uuid=%s\n", uuid);
                extra_root = grub_xasprintf ("root=PARTUUID=%s", uuid);
                grub_free (uuid);
              }
          }
          status = chop_cmdline (uki_cmdline_data, &cmdline_argc, &local_cmdline_argv, (extra_root ? 1 : 0));
          if (status == GRUB_ERR_NONE) {

            if (extra_root)
              local_cmdline_argv[cmdline_argc-1] = extra_root;

            local_cmdline_argv[0] = argv[0];

            cmdline_argv = local_cmdline_argv;
            for (int j = 0; j < cmdline_argc; ++j)
            {
              grub_dprintf ("linux", "arg[%d] = '%s'\n", j, cmdline_argv[j]);
            }

          } else {
            grub_dprintf ("linux", "Error chopping up cmdline from UKI\n");
            return GRUB_ERR_FILE_READ_ERROR;
          }
        }

      len = section_header.raw_data_size;
      grub_file_seek (file, section_header.raw_data_offset);
    }

  kernel = grub_malloc (len);
  if (!kernel)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot allocate kernel buffer"));
      goto fail;
    }

  if (grub_file_read (file, kernel, len) != len)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		    argv[0]);
      goto fail;
    }

  status = prepare_linux (kernel, len, cmdline_argc, cmdline_argv);

  fail:
  grub_file_close (file);
  grub_free (kernel);
  grub_free (local_cmdline_argv);
  grub_free (uki_cmdline_data);
  grub_free (extra_root);

  return status;
}


static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  grub_size_t size = 0;
  grub_addr_t addr_max, addr_min;
  struct linux_i386_kernel_header *lh;
  grub_uint8_t *initrd_chunk;
  grub_addr_t initrd_addr;
  grub_err_t err;
  struct grub_linux_initrd_context initrd_ctx = { 0, 0, 0 };

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  if (!loaded)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("you need to load the kernel first"));
      goto fail;
    }

  lh = (struct linux_i386_kernel_header *) grub_linux_real_chunk;

  if (!(lh->header == grub_cpu_to_le32_compile_time (GRUB_LINUX_I386_MAGIC_SIGNATURE)
	&& grub_le_to_cpu16 (lh->version) >= 0x0200))
    {
      grub_error (GRUB_ERR_BAD_OS, "the kernel is too old for initrd");
      goto fail;
    }

  /* Get the highest address available for the initrd.  */
  if (grub_le_to_cpu16 (lh->version) >= 0x0203)
    {
      addr_max = grub_cpu_to_le32 (lh->initrd_addr_max);

      /* XXX in reality, Linux specifies a bogus value, so
	 it is necessary to make sure that ADDR_MAX does not exceed
	 0x3fffffff.  */
      if (addr_max > GRUB_LINUX_INITRD_MAX_ADDRESS)
	addr_max = GRUB_LINUX_INITRD_MAX_ADDRESS;
    }
  else
    addr_max = GRUB_LINUX_INITRD_MAX_ADDRESS;

  if (linux_mem_size != 0 && linux_mem_size < addr_max)
    addr_max = linux_mem_size;

  /* Linux 2.3.xx has a bug in the memory range check, so avoid
     the last page.
     Linux 2.2.xx has a bug in the memory range check, which is
     worse than that of Linux 2.3.xx, so avoid the last 64kb.  */
  addr_max -= 0x10000;

  addr_min = GRUB_LINUX_BZIMAGE_ADDR + grub_linux16_prot_size;

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  size = grub_get_initrd_size (&initrd_ctx);

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_align_safe (relocator, &ch, addr_min, addr_max, size,
						 0x1000, GRUB_RELOCATOR_PREFERENCE_HIGH, 0);
    if (err)
      return err;
    initrd_chunk = get_virtual_current_address (ch);
    initrd_addr = get_physical_target_address (ch);
  }

  if (grub_initrd_load (&initrd_ctx, argv, initrd_chunk))
    goto fail;

  lh->ramdisk_image = initrd_addr;
  lh->ramdisk_size = size;

 fail:
  grub_initrd_close (&initrd_ctx);

  return grub_errno;
}

static grub_command_t cmd_linux, cmd_linux16, cmd_initrd, cmd_initrd16;

GRUB_MOD_INIT(linux16)
{
  if (grub_efi_get_secureboot () == GRUB_EFI_SECUREBOOT_MODE_ENABLED)
    return;

  cmd_linux =
    grub_register_command ("linux", grub_cmd_linux,
			   0, N_("Load Linux."));
  cmd_linux16 =
    grub_register_command ("linux16", grub_cmd_linux,
			   0, N_("Load Linux."));
  cmd_initrd =
    grub_register_command ("initrd", grub_cmd_initrd,
			   0, N_("Load initrd."));
  cmd_initrd16 =
    grub_register_command ("initrd16", grub_cmd_initrd,
			   0, N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI(linux16)
{
  if (grub_efi_get_secureboot () == GRUB_EFI_SECUREBOOT_MODE_ENABLED)
    return;

  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_linux16);
  grub_unregister_command (cmd_initrd);
  grub_unregister_command (cmd_initrd16);
}
