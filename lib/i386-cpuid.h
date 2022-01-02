#if defined(__GNUC__) && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))

/*
 * GCC's cpuid.h header file is buggy and cannot be included more times.
 * MinGW's intrin.h header file in some versions includes cpuid.h and
 * therefore intrin.h and cpuid.h cannot be mixed in one source unit.
 * libpci's i386-io-windows.h in some cases include intrin.h and therefore
 * in some configurations it is not possible to include cpuid.h here again.
 * GCC's cpuid.h since beginning define __cpuid macro, so it could be used
 * as a include guard. But unfortunately MinGW-w64 since version 10.0.0
 * automatically undefine macro __cpuid in intrin.h.
 */
#if defined(__MINGW64_VERSION_MAJOR) && __MINGW64_VERSION_MAJOR >= 10
#include <intrin.h>
#elif !defined(__cpuid)
#include <cpuid.h>
#endif
#ifndef __get_cpuid
#define __get_cpuid __get_cpuid
#endif

#elif defined (__GNUC__)

static inline int
__get_cpuid(unsigned int level, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
#ifndef __x86_64__
  /* cpuid does not have to be supported on 32-bit x86, check for it. */
  unsigned int eflags_orig, eflags_mod;
  asm (
    "pushfl\n\t"
    "pushfl\n\t"
    "popl\t%0\n\t"
    "movl\t%0, %1\n\t"
    "xorl\t%2, %0\n\t"
    "pushl\t%0\n\t"
    "popfl\n\t"
    "pushfl\n\t"
    "popl\t%0\n\t"
    "popfl\n\t"
      : "=&r" (eflags_mod), "=&r" (eflags_orig)
      : "i" (0x00200000)
  );
  if (!((eflags_mod ^ eflags_orig) & 0x00200000))
    return 0;
#endif

  asm ("cpuid\n\t" : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx) : "0" (level));
  return 1;
}
#define __get_cpuid __get_cpuid

#elif defined(_MSC_VER)

/* MSVC provides intrinsic __cpuid since version 14.00 included in VS2005. */
#if _MSC_VER >= 1400
#pragma intrinsic(__cpuid)
#else
static void
__cpuid(int CPUInfo[4], int InfoType)
{
  __asm {
    mov esi, CPUInfo
    mov eax, InfoType
    xor ecx, ecx
    _emit 0x0F __asm _emit 0xA2 /* cpuid */
    mov dword ptr [esi +  0], eax
    mov dword ptr [esi +  4], ebx
    mov dword ptr [esi +  8], ecx
    mov dword ptr [esi + 12], edx
  }
}
#endif
static inline int
__get_cpuid(unsigned int level, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
  int regs[4];

#ifndef _M_AMD64
  /* cpuid does not have to be supported on 32-bit x86, check for it. */
  unsigned int eflags_orig, eflags_mod;
  __asm {
    pushfd
    pushfd
    pop eflags_orig
    push eflags_orig
    pop eflags_mod
    xor eflags_mod, 0x00200000
    push eflags_mod
    popfd
    pushfd
    pop eflags_mod
    popfd
  }
  if (!((eflags_mod ^ eflags_orig) & 0x00200000))
    return 0;
#endif

  __cpuid(regs, level);
  *eax = regs[0];
  *ebx = regs[1];
  *ecx = regs[2];
  *edx = regs[3];
  return 1;
}
#define __get_cpuid __get_cpuid

#endif
