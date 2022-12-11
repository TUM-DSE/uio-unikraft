#ifndef __USHELL_API__
#define __USHELL_API__

#ifdef __cplusplus
extern "C" {
#endif

void *ushell_alloc_memory(unsigned long size);
void ushell_free_memory(void *addr, unsigned long size);

int ushell_loader_load_elf(char *path);
int ushell_program_run(char *prog_name, int argc, char *argv[], int *retval);
void ushell_program_free_all();

#ifdef __cplusplus
}
#endif

#endif /* __USHELL_API__ */
