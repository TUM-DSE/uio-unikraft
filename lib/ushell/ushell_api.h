#ifndef __USHELL_API__
#define __USHELL_API__

#include <uk/arch/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void *ushell_alloc_memory(unsigned long size);
void ushell_free_memory(void *addr, unsigned long size);

#ifdef __cplusplus
}
#endif

#endif /* __USHELL_API__ */
