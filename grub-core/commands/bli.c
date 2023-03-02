/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023  Free Software Foundation, Inc.
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
 *
 *  Implementation of the Boot Loader Interface.
 */

#include <grub/charset.h>
#include <grub/efi/api.h>
#include <grub/efi/disk.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/gpt_partition.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define MODNAME "bli"

static const grub_guid_t bli_vendor_guid = GRUB_EFI_VENDOR_BOOT_LOADER_INTERFACE_GUID;

/* To be moved to a central place */
static grub_ssize_t
grub_utf8_to_utf16_alloc (const char *str8, grub_uint16_t **utf16_msg, grub_uint16_t **last_position)
{
  grub_size_t len;
  grub_size_t len16;

  len = grub_strlen (str8);

  /* Check for integer overflow */
  if (len > GRUB_SSIZE_MAX / GRUB_MAX_UTF16_PER_UTF8 - 1)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("string too large"));
      *utf16_msg = NULL;
      return -1;
    }

  len16 = len * GRUB_MAX_UTF16_PER_UTF8;

  *utf16_msg = grub_calloc (len16 + 1, sizeof (*utf16_msg[0]));
  if (*utf16_msg == NULL)
    return -1;

  len16 = grub_utf8_to_utf16 (*utf16_msg, len16, (grub_uint8_t *) str8, len, NULL);

  if (last_position)
    *last_position = *utf16_msg + len16;

  return len16;
}

static grub_err_t
get_part_uuid (grub_device_t dev, char **part_uuid)
{
  grub_err_t status = GRUB_ERR_NONE;
  grub_disk_t disk;
  struct grub_gpt_partentry entry;

  if (dev == NULL || dev->disk == NULL || dev->disk->partition == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid device"));

  disk = grub_disk_open (dev->disk->name);
  if (disk == NULL)
    {
      status = grub_errno;
      char *part = grub_partition_get_name (dev->disk->partition);
      grub_dprintf (MODNAME, "error opening disk: %s%s%s\n", dev->disk->name,
		    dev->disk->partition != NULL ? "," : "",
		    part != NULL ? part : "UNKNOWN");
      grub_free (part);
      return status;
    }

  if (grub_strcmp (dev->disk->partition->partmap->name, "gpt") != 0)
    {
      char *part = grub_partition_get_name (dev->disk->partition);
      status = grub_error (GRUB_ERR_BAD_PART_TABLE,
		           "this is not a GPT partition table: %s%s%s", dev->disk->name,
			   dev->disk->partition != NULL ? "," : "",
			   part != NULL ? part : "UNKNOWN");
      grub_free (part);
      goto fail;
    }

  if (grub_disk_read (disk, dev->disk->partition->offset,
		      dev->disk->partition->index, sizeof (entry), &entry) != GRUB_ERR_NONE)
    {
      status = grub_errno;
      char *part = grub_partition_get_name (dev->disk->partition);
      grub_dprintf (MODNAME, "read error: %s%s%s\n", dev->disk->name,
		    dev->disk->partition != NULL ? "," : "",
		    part != NULL ? part : "UNKNOWN");
      grub_free (part);
      goto fail;
    }

  *part_uuid = grub_xasprintf ("%pG", &entry.guid);
  if (*part_uuid == NULL)
    status = grub_errno;

 fail:
  grub_disk_close (disk);

  return status;
}


static grub_err_t
set_efi_str_variable (const char *name, const grub_guid_t *guid,
                      const char *value)
{
  grub_efi_char16_t *value_16;
  grub_ssize_t len16;
  grub_err_t status;

  len16 = grub_utf8_to_utf16_alloc (value, &value_16, NULL);

  if (len16 < 0)
    return grub_errno;

  status = grub_efi_set_variable_with_attributes (name, guid,
			(void *) value_16, (len16 + 1) * sizeof (value_16[0]),
			GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS
			| GRUB_EFI_VARIABLE_RUNTIME_ACCESS);
  if (status != GRUB_ERR_NONE)
    grub_dprintf (MODNAME, "Error setting EFI variable %s: %d\n", name, status);

  grub_free (value_16);

  return status;
}

static grub_err_t
set_loader_device_part_uuid (void)
{
  grub_efi_loaded_image_t *image;
  char *device_name;
  grub_err_t status = GRUB_ERR_NONE;
  grub_device_t device;
  char *part_uuid = NULL;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (image == NULL)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("unable to find boot device"));

  device_name = grub_efidisk_get_device_name (image->device_handle);
  if (device_name == NULL)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("unable to find boot device"));

  device = grub_device_open (device_name);
  if (device == NULL)
    {
      status = grub_errno;
      grub_dprintf (MODNAME, "Error opening device: %s", device_name);
      goto fail;
    }

  status = get_part_uuid (device, &part_uuid);

  grub_device_close (device);

  if (status == GRUB_ERR_NONE)
    status = set_efi_str_variable ("LoaderDevicePartUUID",
				   &bli_vendor_guid,
				   part_uuid);

 fail:
  grub_free (part_uuid);
  grub_free (device_name);
  return status;
}

static grub_err_t
grub_cmd_bli (grub_extcmd_context_t ctxt __attribute__ ((unused)),
	      int argc __attribute__ ((unused)),
	      char **args __attribute__ ((unused)))
{
  grub_err_t status;

  status = set_efi_str_variable ("LoaderInfo", &bli_vendor_guid, PACKAGE_STRING);
  if (status != GRUB_ERR_NONE)
    return status;

  status = set_loader_device_part_uuid ();
  if (status != GRUB_ERR_NONE)
    return status;

  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT (bli)
{
  grub_dprintf (MODNAME, "%s got here\n", __func__);
  cmd = grub_register_extcmd ("bli", grub_cmd_bli, 0, NULL,
			      N_("Set EFI variables according to Boot Loader Interface spec."), NULL);
}

GRUB_MOD_FINI (bli)
{
  grub_unregister_extcmd (cmd);
}

