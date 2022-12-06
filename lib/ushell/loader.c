#include "elf.h"

#include <string.h> // strncpy

#ifdef USHELL_LOADER_TEST

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#define UK_ASSERT assert
#define USHELL_LOADER_PRRINT printf
#define USHELL_LOADER_PR_DEBUG printf
#define USHELL_LOADER_PR_ERR printf

void uk_console_puts(char *buf, int n);

void *ushell_alloc_memory(unsigned long size)
{
	return malloc(size);
}

void ushell_free_memory(void *addr, unsigned long size __attribute__((unused)))
{
	free(addr);
}

#else // USHELL_LOADER_TEST

#include <ushell/ushell.h>
#include "ushell_api.h"

#include <uk/assert.h>
#include <uk/print.h>
#include <uk/essentials.h>
#include <uk/arch/limits.h>

#define USHELL_LOADER_PRRINT uk_printk
#define USHELL_LOADER_PR_DEBUG uk_pr_debug
#define USHELL_LOADER_PR_ERR uk_pr_err

#endif

void *ushell_symbol_get(const char *symbol)
{
	void *addr = NULL;

	UK_ASSERT(symbol);

	if (!strncmp(symbol, "uk_console_puts", 15)) {
		addr = (void *)uk_console_puts;
	}

	return addr;
}

/* -------------------------------------------- */

#ifdef USHELL_LOADER_TEST

void uk_console_puts(char *buf, int n)
{
	int i = 0;
	for (i = 0; i < n; i++) {
		putc(buf[i], stdout);
	}
}

void load_elf_binary(char *path, void **elf_img, size_t *elf_size)
{
	int fd = open(path, O_RDONLY);
	assert(fd > 0);
	struct stat sb;
	fstat(fd, &sb);

	printf("file: %s, size: %ld\n", path, sb.st_size);
	void *addr = NULL;
	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(addr != MAP_FAILED && addr != 0);

	*elf_size = sb.st_size;
	*elf_img = addr;
}

void reloc_elf()
{
	/* NOTE: recent compiler uses R_X86_64_PLT32 instead of R_X86_64_PC32 to
	 * mark 32-bit PC-relative branches.
	 * "Linker can always reduce PLT32 relocation to PC32 if function is
	 * defined locally." cf.
	 * https://sourceware.org/git/?p=binutils-gdb.git;a=commitdiff;h=bd7ab16b4537788ad53521c45469a1bdae84ad4a;hp=80c96350467f23a54546580b3e2b67a65ec65b66
	 *
	 * R_X86_64_PC32: S + A - P
	 *     S: st_value (symbol address)
	 *     A: addend
	 *     P: the address of the memory location being relocated
	 *
	 * R_X86_64_GOTPCREL: G + GOT + A - P
	 *    G: offset to the GOT relative to the address of the symbol
	 *    GOT: address of the GOT
	 */
}

int execute_func(void *code, int argc, char *argv[])
{
	int (*func)(int, char *[]) = code;
	int r = func(argc, argv);
	return r;
}

void run_elf(void *elf_img, size_t elf_size, int argc, char *argv[])
{
	assert(elf_img);
	Elf64_Ehdr *ehdr = elf_img;
	assert(ehdr->e_ident[0] == 0x7f && ehdr->e_ident[1] == 'E'
	       && ehdr->e_ident[2] == 'L' && ehdr->e_ident[3] == 'F');
	assert(ehdr->e_machine == EM_AMD64);
	assert(ehdr->e_type == ET_REL);

	// scan sections
	int i, txt_idx = -1, sym_idx = -1, str_idx = -1;
	Elf64_Shdr *shdr, *shstr_shdr, *str_shdr, *txt_shdr, *sym_shdr;
	printf("section num: %d\n", ehdr->e_shnum);
	printf("string table idx: %d\n", ehdr->e_shstrndx);
	shdr = elf_img + ehdr->e_shoff;
	shstr_shdr = shdr + ehdr->e_shstrndx;
	char *shstrtab = elf_img + shstr_shdr->sh_offset;
	for (i = 0; i < ehdr->e_shnum; i++) {
		char *shname = shstrtab + shdr->sh_name;
		printf("seciton %d: %s\n", i, shname);
		if (!strcmp(shname, ".text")) {
			txt_shdr = shdr;
			txt_idx = i;
		} else if (!strcmp(shname, ".symtab")) {
			sym_shdr = shdr;
			sym_idx = i;
		} else if (!strcmp(shname, ".strtab")) {
			str_shdr = shdr;
			str_idx = i;
		}
		shdr++;
	}
	assert(txt_idx != -1 && sym_idx != -1);

	printf("found text section: id=%d, offset=%ld, size=%ld\n", txt_idx,
	       txt_shdr->sh_offset, txt_shdr->sh_size);

	int sym_entries = sym_shdr->sh_size / sym_shdr->sh_entsize;
	printf(
	    "found symbol table section: id=%d, offset=%ld, size=%ld, num=%d\n",
	    sym_idx, sym_shdr->sh_offset, sym_shdr->sh_size, sym_entries);

	// scan symbol section (search entry point)
	Elf64_Sym *sym = elf_img + sym_shdr->sh_offset;
	Elf64_Sym *main_sym = NULL;
	for (i = 0; i < sym_entries; i++, sym++) {
		char *name = sym->st_name == 0
				 ? "<noname>"
				 : (char *)(elf_img + str_shdr->sh_offset
					    + sym->st_name);
		printf(
		    "symbol %d: %s, size=%ld, value=%ld, type=%d, shndx=%x\n",
		    i, name, sym->st_size, sym->st_value, sym->st_info & 0xf,
		    sym->st_shndx);
		if (!strncmp(name, "main", 4)) {
			main_sym = sym;
		}
	}

	assert(main_sym);

	// load
	void *code = mmap(NULL, elf_size, PROT_WRITE | PROT_EXEC,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(code != MAP_FAILED);
	memcpy(code, elf_img + txt_shdr->sh_offset, txt_shdr->sh_size);

	// run
	int r = execute_func(code + main_sym->st_value, argc, argv);
	printf("return value: %d\n", r);

	// clean up
	munmap(code, elf_size);
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		printf("Usage: %s <prog> [option...]\n", argv[0]);
		return 0;
	}
	char *prog = argv[1];

	void *elf_img, *code;
	size_t size;
	load_elf_binary(prog, &elf_img, &size);
	run_elf(elf_img, size, argc - 1, argv + 1);
	munmap(elf_img, size);

	return 0;
}

#endif // USHELL_LOADER_TEST
