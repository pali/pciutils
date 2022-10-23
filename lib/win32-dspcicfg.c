/*
 *      The PCI Library -- PCI config space access using DsPciCfg kernel driver
 *
 *      Copyright (c) 2022 Pali Rohár <pali@kernel.org>
 *
 *      Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <windows.h>
#include <winioctl.h>

#include <stdio.h> /* for sprintf() */
#include <string.h> /* for memset() and memcpy() */

#include "internal.h"

#define IOCTL_DSPCICFG_GETNUMPCIBUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222000 */
#define IOCTL_DSPCICFG_GETPCIDEVLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222004 */
#define IOCTL_DSPCICFG_GETPCIDEVINFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222008 */
#define IOCTL_DSPCICFG_SETPCIDEVREG  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x22200C */

struct DsPciCfgGetData
{
  ULONG BusNumber;
  ULONG DeviceNumber;
  ULONG FunctionNumber;
  BYTE Padding[128-3*sizeof(ULONG)]; /* See win32_dspcicfg_read() for explanation */
};

struct DsPciCfgSetData
{
  ULONG BusNumber;
  ULONG DeviceNumber;
  ULONG FunctionNumber;
  ULONG Offset;
  ULONG BufferLength;
  BYTE Buffer[0];
};

static const char *
win32_strerror(DWORD win32_error_id)
{
  /*
   * Use static buffer which is large enough.
   * Hopefully no Win32 API error message string is longer than 4 kB.
   */
  static char buffer[4096];
  DWORD len;

  len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, win32_error_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), NULL);

  /* FormatMessage() automatically appends ".\r\n" to the error message. */
  if (len && buffer[len-1] == '\n')
    buffer[--len] = '\0';
  if (len && buffer[len-1] == '\r')
    buffer[--len] = '\0';
  if (len && buffer[len-1] == '.')
    buffer[--len] = '\0';

  if (!len)
    sprintf(buffer, "Unknown Win32 error %lu", win32_error_id);

  return buffer;
}

static HANDLE dspcicfg_dev = INVALID_HANDLE_VALUE;

static int
win32_dspcicfg_start_driver(struct pci_access *a)
{
  SC_HANDLE manager = NULL;
  SC_HANDLE service = NULL;
  DWORD error = 0;
  int ret = 0;

  manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (!manager)
    {
      a->debug("Cannot open Service Manager: %s.", win32_strerror(GetLastError()));
      return 0;
    }

  service = OpenService(manager, TEXT("DsPciCfg"), SERVICE_START);
  if (!service)
    {
      error = GetLastError();
      if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        a->debug("Cannot open DsPciCfg service: DsPciCfg kernel driver is not installed.");
      else
        a->debug("Cannot open DsPciCfg service: %s.", win32_strerror(error));
      goto out;
    }

  if (!StartService(service, 0, NULL))
    {
      error = GetLastError();
      if (error != ERROR_SERVICE_ALREADY_RUNNING)
        {
          a->debug("Cannot start DsPciCfg service: %s.", win32_strerror(error));
          goto out;
        }
    }

  a->debug("Service DsPciCfg successfully started...");
  ret = 1;

out:
  if (service)
    CloseServiceHandle(service);

  if (manager)
    CloseServiceHandle(manager);

  return ret;
}

static int
win32_dspcicfg_setup(struct pci_access *a)
{
  DWORD error;

  if (dspcicfg_dev != INVALID_HANDLE_VALUE)
    return 1;

  dspcicfg_dev = CreateFile(TEXT("\\\\.\\DsPciCfg"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (dspcicfg_dev == INVALID_HANDLE_VALUE)
    {
      error = GetLastError();
      if (error != ERROR_FILE_NOT_FOUND)
        {
          a->debug("Cannot open \"\\\\.\\DsPciCfg\" device: %s.", win32_strerror(error));
          return 0;
        }

      if (!win32_dspcicfg_start_driver(a))
        return 0;

      dspcicfg_dev = CreateFile(TEXT("\\\\.\\DsPciCfg"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (dspcicfg_dev == INVALID_HANDLE_VALUE)
        {
          error = GetLastError();
          a->debug("Cannot open \"\\\\.\\DsPciCfg\" device: %s.", win32_strerror(error));
          return 0;
        }
    }

  return 1;
}

static int
win32_dspcicfg_detect(struct pci_access *a)
{
  if (!win32_dspcicfg_setup(a))
    return 0;

  return 1;
}

static void
win32_dspcicfg_init(struct pci_access *a)
{
  if (!win32_dspcicfg_setup(a))
    {
      a->debug("\n");
      a->error("PCI config space via DsPciCfg kernel driver cannot be accessed.");
    }
}

static void
win32_dspcicfg_cleanup(struct pci_access *a UNUSED)
{
  if (dspcicfg_dev == INVALID_HANDLE_VALUE)
    return;

  CloseHandle(dspcicfg_dev);
  dspcicfg_dev = INVALID_HANDLE_VALUE;
}

static int
win32_dspcicfg_read(struct pci_dev *d, int pos, byte *buf, int len)
{
  struct DsPciCfgGetData data;
  byte *out_buf;
  DWORD out_buf_len;
  DWORD ret_len;
  BOOL success;

  if (d->domain != 0)
    return 0;

  /*
   * DsPciCfg kernel driver has strange read API.
   *
   * It can read PCI config space only from beginning. So if were are asked to
   * read from non-zero position then allocate temporary output buffer, read all
   * registers from the beginning and copy only requested content to the
   * caller's buffer.
   *
   * It mark every read request for 2 bytes or less as failure. So always read
   * at least 4 bytes from config space.
   *
   * For PCI devices which have in their config space first word 0x1000 (which
   * implies Broadcom PCI vendor ID) driver expects that passed output buffer is
   * exactly 128 bytes long and completely ignores supplied output buffer length.
   * Hence it is not possible to read any register after 128 byte offset for
   * Broadcom PCI devices. And because we do not know what is stored in PCI
   * vendor ID register before reading it, we have to always supply at least
   * 128 bytes long output buffer. This IoControl is METHOD_BUFFERED, so it
   * shares input and output buffers at kernel level. Therefore it is enough
   * to always supply 128 bytes long input buffer.
   */

  memset(&data, 0, sizeof(data));
  data.BusNumber = d->bus;
  data.DeviceNumber = d->dev;
  data.FunctionNumber = d->func;

  if (pos != 0 || len <= 2)
    {
      out_buf_len = pos + len;
      if (out_buf_len <= 2)
        out_buf_len = 4;
      out_buf = pci_malloc(d->access, out_buf_len);
    }
  else
    {
      out_buf_len = len;
      out_buf = buf;
    }

  ret_len = 0;
  success = DeviceIoControl(dspcicfg_dev, IOCTL_DSPCICFG_GETPCIDEVINFO, &data, sizeof(data), out_buf, out_buf_len, &ret_len, NULL);

  if (success && ret_len < (unsigned int)(pos + len))
    success = 0;

  if (pos != 0 || len <= 2)
    {
      if (success)
        memcpy(buf, out_buf + pos, len);
      pci_mfree(out_buf);
    }

  if (!success)
    return 0;

  return 1;
}

static int
win32_dspcicfg_write(struct pci_dev *d, int pos, byte *buf, int len)
{
  struct DsPciCfgSetData *data;
  DWORD data_len;
  DWORD ret_len;
  BOOL success;

  if (d->domain != 0)
    return 0;

  /*
   * DsPciCfg kernel driver has strange write API. Passed buffer must be always
   * at least 2 bytes (= 1 word) long even when going to write just one byte.
   * And if first word in buffer is 0x1000 then driver expects that passed buffer
   * is exactly 128 bytes long and completely ignores supplied buffer length.
   * Hence it is not possible to write buffer content which begins with word
   * 0x1000 and is not 128 bytes long. So split it into more write calls.
   */

  if (len >= 2 && len != 128 && buf[0] == 0x00 && buf[1] == 0x10)
    {
      if (!win32_dspcicfg_write(d, pos, buf, 1))
        return 0;
      pos++; buf++, len--;

      if (!win32_dspcicfg_write(d, pos, buf, 1))
        return 0;
      pos++; buf++, len--;

      if ((pos & 3) && len >= 2)
        {
          if (!win32_dspcicfg_write(d, pos, buf, 2))
            return 0;
          pos += 2; buf += 2; len -= 2;
        }

      if (len == 0)
        return 1;

      return win32_dspcicfg_write(d, pos, buf, len);
    }

  data_len = sizeof(*data) + len;
  if (len == 1)
    data_len++;
  data = pci_malloc(d->access, data_len);
  memset(data, 0, sizeof(*data));
  data->BusNumber = d->bus;
  data->DeviceNumber = d->dev;
  data->FunctionNumber = d->func;
  data->Offset = pos;
  data->BufferLength = len;
  memcpy(data->Buffer, buf, len);

  ret_len = 0;
  success = DeviceIoControl(dspcicfg_dev, IOCTL_DSPCICFG_SETPCIDEVREG, data, data_len, NULL, 0, &ret_len, NULL);

  pci_mfree(data);

  if (!success || ret_len != (unsigned int)len)
    return 0;

  return 1;
}

struct pci_methods pm_win32_dspcicfg = {
  "win32-dspcicfg",
  "Win32 PCI config space access using DsPciCfg kernel driver",
  NULL,					/* config */
  win32_dspcicfg_detect,
  win32_dspcicfg_init,
  win32_dspcicfg_cleanup,
  pci_generic_scan,
  pci_generic_fill_info,
  win32_dspcicfg_read,
  win32_dspcicfg_write,
  NULL,					/* read_vpd */
  NULL,					/* init_dev */
  NULL					/* cleanup_dev */
};
