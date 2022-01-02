/*
 *	The PCI Library -- Direct Configuration access via i386 Ports
 *
 *	Copyright (c) 1997--2006 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define _GNU_SOURCE

#include "internal.h"

#include <string.h>

#if defined(PCI_OS_LINUX)
#include "i386-io-linux.h"
#elif defined(PCI_OS_GNU)
#include "i386-io-hurd.h"
#elif defined(PCI_OS_SUNOS)
#include "i386-io-sunos.h"
#elif defined(PCI_OS_WINDOWS)
#include "i386-io-windows.h"
#elif defined(PCI_OS_CYGWIN)
#include "i386-io-cygwin.h"
#elif defined(PCI_OS_HAIKU)
#include "i386-io-haiku.h"
#elif defined(PCI_OS_BEOS)
#include "i386-io-beos.h"
#elif defined(PCI_OS_DJGPP)
#include "i386-io-djgpp.h"
#else
#error Do not know how to access I/O ports on this OS.
#endif

#include "i386-cpuid.h"

static int conf12_io_enabled = -1;		/* -1=haven't tried, 0=failed, 1=succeeded */

static int
conf12_setup_io(struct pci_access *a)
{
  if (conf12_io_enabled < 0)
    conf12_io_enabled = intel_setup_io(a);
  return conf12_io_enabled;
}

static void
conf12_init(struct pci_access *a)
{
  if (!conf12_setup_io(a))
  {
    a->debug("\n");
    a->error("No permission to access I/O ports (you probably have to be root).");
  }
}

static void
conf12_cleanup(struct pci_access *a)
{
  if (conf12_io_enabled > 0)
    {
      intel_cleanup_io(a);
      conf12_io_enabled = -1;
    }
}

/*
 * Before we decide to use direct hardware access mechanisms, we try to do some
 * trivial checks to ensure it at least _seems_ to be working -- we just test
 * whether bus 00 contains a host bridge (this is similar to checking
 * techniques used in XFree86, but ours should be more reliable since we
 * attempt to make use of direct access hints provided by the PCI BIOS).
 *
 * This should be close to trivial, but it isn't, because there are buggy
 * chipsets (yes, you guessed it, by Intel and Compaq) that have no class ID.
 */

static int
intel_sanity_check(struct pci_access *a, struct pci_methods *m)
{
  struct pci_dev d;

  memset(&d, 0, sizeof(d));
  a->debug("...sanity check");
  d.bus = 0;
  d.func = 0;
  for (d.dev = 0; d.dev < 32; d.dev++)
    {
      u16 class, vendor;
      if (m->read(&d, PCI_CLASS_DEVICE, (byte *) &class, sizeof(class)) &&
	  (class == cpu_to_le16(PCI_CLASS_BRIDGE_HOST) || class == cpu_to_le16(PCI_CLASS_DISPLAY_VGA)) ||
	  m->read(&d, PCI_VENDOR_ID, (byte *) &vendor, sizeof(vendor)) &&
	  (vendor == cpu_to_le16(PCI_VENDOR_ID_INTEL) || vendor == cpu_to_le16(PCI_VENDOR_ID_COMPAQ)))
	{
	  a->debug("...outside the Asylum at 0/%02x/0", d.dev);
	  return 1;
	}
    }
  a->debug("...insane");
  return 0;
}

/*
 *	Configuration type 1
 */

static int
conf1_detect(struct pci_access *a)
{
  unsigned int tmp;
  int res = 0;

  if (!conf12_setup_io(a))
    {
      a->debug("...no I/O permission");
      return 0;
    }

  intel_io_lock();
  outb (0x01, 0xCFB);
  tmp = inl (0xCF8);
  outl (0x80000000, 0xCF8);
  if (inl (0xCF8) == 0x80000000)
    res = 1;
  outl (tmp, 0xCF8);
  intel_io_unlock();

  if (res)
    res = intel_sanity_check(a, &pm_intel_conf1);
  return res;
}

static int
conf1_ext_read(struct pci_dev *d, int pos, byte *buf, int len)
{
  int addr = 0xcfc + (pos&3);
  int res = 1;

  if (d->domain || pos >= 4096)
    return 0;

  if (len != 1 && len != 2 && len != 4)
    return pci_generic_block_read(d, pos, buf, len);

  intel_io_lock();
  outl(0x80000000 | ((pos & 0xf00) << 16) | ((d->bus & 0xff) << 16) | (PCI_DEVFN(d->dev, d->func) << 8) | (pos & 0xfc), 0xcf8);

  switch (len)
    {
    case 1:
      buf[0] = inb(addr);
      break;
    case 2:
      ((u16 *) buf)[0] = cpu_to_le16(inw(addr));
      break;
    case 4:
      ((u32 *) buf)[0] = cpu_to_le32(inl(addr));
      break;
    }

  intel_io_unlock();
  return res;
}

static int
conf1_read(struct pci_dev *d, int pos, byte *buf, int len)
{
  if (pos >= 256)
    return 0;

  return conf1_ext_read(d, pos, buf, len);
}

static int
conf1_ext_write(struct pci_dev *d, int pos, byte *buf, int len)
{
  int addr = 0xcfc + (pos&3);
  int res = 1;

  if (d->domain || pos >= 4096)
    return 0;

  if (len != 1 && len != 2 && len != 4)
    return pci_generic_block_write(d, pos, buf, len);

  intel_io_lock();
  outl(0x80000000 | ((pos & 0xf00) << 16) | ((d->bus & 0xff) << 16) | (PCI_DEVFN(d->dev, d->func) << 8) | (pos & 0xfc), 0xcf8);

  switch (len)
    {
    case 1:
      outb(buf[0], addr);
      break;
    case 2:
      outw(le16_to_cpu(((u16 *) buf)[0]), addr);
      break;
    case 4:
      outl(le32_to_cpu(((u32 *) buf)[0]), addr);
      break;
    }
  intel_io_unlock();
  return res;
}

static int
conf1_write(struct pci_dev *d, int pos, byte *buf, int len)
{
  if (pos >= 256)
    return 0;

  return conf1_ext_write(d, pos, buf, len);
}

/*
 *	Configuration type 2. Obsolete and brain-damaged, but existing.
 */

static int
conf2_detect(struct pci_access *a)
{
  int res = 0;

  if (!conf12_setup_io(a))
    {
      a->debug("...no I/O permission");
      return 0;
    }

  /* This is ugly and tends to produce false positives. Beware. */

  intel_io_lock();
  outb(0x00, 0xCFB);
  outb(0x00, 0xCF8);
  outb(0x00, 0xCFA);
  if (inb(0xCF8) == 0x00 && inb(0xCFA) == 0x00)
    res = intel_sanity_check(a, &pm_intel_conf2);
  intel_io_unlock();
  return res;
}

static int
conf2_read(struct pci_dev *d, int pos, byte *buf, int len)
{
  int res = 1;
  int addr = 0xc000 | (d->dev << 8) | pos;

  if (d->domain || pos >= 256)
    return 0;

  if (d->dev >= 16)
    /* conf2 supports only 16 devices per bus */
    return 0;

  if (len != 1 && len != 2 && len != 4)
    return pci_generic_block_read(d, pos, buf, len);

  intel_io_lock();
  outb((d->func << 1) | 0xf0, 0xcf8);
  outb(d->bus, 0xcfa);
  switch (len)
    {
    case 1:
      buf[0] = inb(addr);
      break;
    case 2:
      ((u16 *) buf)[0] = cpu_to_le16(inw(addr));
      break;
    case 4:
      ((u32 *) buf)[0] = cpu_to_le32(inl(addr));
      break;
    }
  outb(0, 0xcf8);
  intel_io_unlock();
  return res;
}

static int
conf2_write(struct pci_dev *d, int pos, byte *buf, int len)
{
  int res = 1;
  int addr = 0xc000 | (d->dev << 8) | pos;

  if (d->domain || pos >= 256)
    return 0;

  if (d->dev >= 16)
    /* conf2 supports only 16 devices per bus */
    return 0;

  if (len != 1 && len != 2 && len != 4)
    return pci_generic_block_write(d, pos, buf, len);

  intel_io_lock();
  outb((d->func << 1) | 0xf0, 0xcf8);
  outb(d->bus, 0xcfa);
  switch (len)
    {
    case 1:
      outb(buf[0], addr);
      break;
    case 2:
      outw(le16_to_cpu(* (u16 *) buf), addr);
      break;
    case 4:
      outl(le32_to_cpu(* (u32 *) buf), addr);
      break;
    }

  outb(0, 0xcf8);
  intel_io_unlock();
  return res;
}

static int cpu_detected = -1;
static int cpu_needs_setup = 0;
static int
conf1_ext_detect_cpu(struct pci_access *a)
{
#ifdef __get_cpuid
  unsigned int eax, ebx, ecx, edx;
  unsigned int family;
#endif

  if (cpu_detected >= 0)
    goto out;

#ifndef __get_cpuid
  a->debug("...cannot determinate CPU model");
  cpu_detected = 0;
  goto out;
#else
  if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx))
    {
      a->debug("...detected unsupported CPU without cpuid instruction");
      cpu_detected = 0;
      goto out;
    }

  /* Check for AuthenticAMD or HygonGenuine signature. */
  if ((ebx != 0x68747541 || edx != 0x69746E65 || ecx != 0x444D4163) &&
      (ebx != 0x6f677948 || edx != 0x6e65476e || ecx != 0x656e6975))
    {
      a->debug("...detected unsupported CPU %.4s%.4s%.4s", (char *)&ebx, (char *)&edx, (char *)&ecx);
      cpu_detected = 0;
      goto out;
    }

  /* Get the CPU family number. */
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
    {
      a->debug("...detected unsupported CPU AMD/Hygon");
      cpu_detected = 0;
      goto out;
    }
  family = (eax >> 8) & 0xf;
  if (family == 0xf)
    family += (eax >> 20) & 0xff;

  /* For now only AMD Family 10h and higher CPUs are supported. */
  if (family < 0x10)
    {
      a->debug("...detected unsupported CPU AMD Family %xh", family);
      cpu_detected = 0;
      goto out;
    }

  /* AMD Family 10h - 16h needs special setup. */
  if (family < 0x17)
    cpu_needs_setup = 1;

  a->debug("...detected supported CPU AMD Family %xh", family);
  cpu_detected = 1;
  goto out;
#endif

out:
  return cpu_detected;
}

static int
conf1_ext_setup(struct pci_access *a)
{
  struct pci_dev d;
  u32 nbcfg1;
  u32 val;

  /*
   * AMD Family 10h - 16h:
   * EnableCf8ExtCfg bit [46] in NB Configuration 1 [NB_CFG1] register controls
   * whether CF8 extended configuration cycles are enabled or not. This 64-bit
   * register is mapped to MSR register [MSRC001_001F] and its upper 32 bits
   * also to PCI register [D18F3x8C]. That PCI register is in config space of
   * bus 0x00 device 0x18 function 0x3 offset 0x8c.
   * AMD Family 17h+:
   * No special setup is required, ExtRegNo is always enabled and supported.
   * References:
   * BIOS and Kernel Developer’s Guide (BKDG) For AMD Family 10h-16h Processors
   * Processor Programming Reference (PPR) for AMD Family 17h-19h Processors
   * https://developer.amd.com/resources/developer-guides-manuals/
   */

  if (!cpu_needs_setup)
    {
      a->debug("...no setup required");
      goto verify;
    }

  memset(&d, 0, sizeof(d));
  d.bus = 0;
  d.dev = 0x18;
  d.func = 0x3;

  a->debug("...reading NB_CFG1");
  if (!conf1_read(&d, 0x8c, (byte *)&nbcfg1, sizeof(nbcfg1)))
    {
      a->debug("...failed");
      return 0;
    }

  if (!(nbcfg1 & (1 << (46 - 32))))
    {
      a->debug("...EnableCf8ExtCfg unset");
      nbcfg1 |= (1 << (46 - 32));
      a->debug("...setting EnableCf8ExtCfg in NB_CFG1");
      if (!conf1_write(&d, 0x8c, (byte *)&nbcfg1, sizeof(nbcfg1)))
        {
          a->debug("...failed");
          return 0;
        }
      a->debug("...reading NB_CFG1");
      if (!conf1_read(&d, 0x8c, (byte *)&nbcfg1, sizeof(nbcfg1)))
        {
          a->debug("...failed");
          return 0;
        }
      a->debug("...verifying EnableCf8ExtCfg");
      if (!(nbcfg1 & (1 << (46 - 32))))
        {
          a->debug("...failed");
          return 0;
        }
      a->debug("...passed");
    }
  else
    a->debug("...EnableCf8ExtCfg already set");

verify:
  /*
   * Set CF8 address to the first register from extended config space (0x100)
   * and verify that address was set the correct value. When Cf8ExtCfg access
   * is unsupported or not enabled then CF8 address bits for extended config
   * space cannot be set and are hardwired to zeros.
   */
  a->debug("...verifying Cf8ExtCfg access");
  intel_io_lock();
  outl(0x81000000, 0xcf8);
  val = inl(0xcf8);
  intel_io_unlock();
  if (val != 0x81000000)
    {
      a->debug("...failed");
      return 0;
    }
  a->debug("...passed");

  return 1;
}

static void
conf1_ext_init(struct pci_access *a)
{
  if (cpu_detected < 0)
    {
      a->debug("detecting CPU");
      conf1_ext_detect_cpu(a);
    }
  if (!cpu_detected)
    {
      a->debug("\n");
      a->error("Unsupported CPU for Intel conf1 extended interface (requires AMD Family 10h or higher).");
    }

  conf12_init(a);

  if (!conf1_ext_setup(a))
    {
      a->debug("\n");
      a->error("Cannot setup Intel conf1 extended interface (probably not supported).");
    }
}

static int
conf1_ext_detect(struct pci_access *a)
{
  if (!conf1_ext_detect_cpu(a))
    return 0;

  if (!conf1_detect(a))
    return 0;

  if (!conf1_ext_setup(a))
    return 0;

  return 1;
}

struct pci_methods pm_intel_conf1 = {
  "intel-conf1",
  "Raw I/O port access using Intel conf1 interface",
  NULL,					/* config */
  conf1_detect,
  conf12_init,
  conf12_cleanup,
  pci_generic_scan,
  pci_generic_fill_info,
  conf1_read,
  conf1_write,
  NULL,					/* read_vpd */
  NULL,					/* init_dev */
  NULL					/* cleanup_dev */
};

struct pci_methods pm_intel_conf1_ext = {
  "intel-conf1-ext",
  "Raw I/O port access using Intel conf1 extended interface",
  NULL,					/* config */
  conf1_ext_detect,
  conf1_ext_init,
  conf12_cleanup,
  pci_generic_scan,
  pci_generic_fill_info,
  conf1_ext_read,
  conf1_ext_write,
  NULL,					/* read_vpd */
  NULL,					/* init_dev */
  NULL					/* cleanup_dev */
};

struct pci_methods pm_intel_conf2 = {
  "intel-conf2",
  "Raw I/O port access using Intel conf2 interface",
  NULL,					/* config */
  conf2_detect,
  conf12_init,
  conf12_cleanup,
  pci_generic_scan,
  pci_generic_fill_info,
  conf2_read,
  conf2_write,
  NULL,					/* read_vpd */
  NULL,					/* init_dev */
  NULL					/* cleanup_dev */
};
