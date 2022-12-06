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

#define USHELL_PROG_MAX_NUM 16
#define USHELL_PROG_NAME_MAX 16
struct ushell_program {
	char name[USHELL_PROG_NAME_MAX];
	void *text;
	void *data;
	void *bss;
	void *rodata;
	size_t text_size;
	size_t data_size;
	size_t bss_size;
	size_t rodata_size;
	uint64_t entry_off;
};

int ushell_program_current_idx;
struct ushell_program ushell_programs[USHELL_PROG_MAX_NUM];

static struct ushell_program *ushell_program_find(char *name)
{
	int i;
	for (i = 0; i < ushell_program_current_idx; i++) {
		if (!strncmp(ushell_programs[i].name, name,
			     USHELL_PROG_NAME_MAX)) {
			return &ushell_programs[i];
		}
	}
	return NULL;
}

static void ushell_program_init(char *name, struct ushell_program *prog)
{
	memcpy(prog->name, name, USHELL_PROG_NAME_MAX);
	prog->text = NULL;
	prog->data = NULL;
	prog->bss = NULL;
	prog->rodata = NULL;
	prog->text_size = 0;
	prog->data_size = 0;
	prog->bss_size = 0;
	prog->rodata_size = 0;
	prog->entry_off = 0;
}

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

static void reloc_elf()
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

static void ushell_program_load_elf(char *path)
{
	assert(ushell_program_current_idx < USHELL_PROG_MAX_NUM);

	struct ushell_program *prog =
	    &ushell_programs[ushell_program_current_idx];
	ushell_program_init(path, prog);

	int fd = open(path, O_RDONLY);
	assert(fd > 0);
	struct stat sb;
	fstat(fd, &sb);

	printf("file: %s, size: %ld\n", path, sb.st_size);
	void *elf_img = NULL;
	size_t elf_size = sb.st_size;
	elf_img = mmap(NULL, elf_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(elf_img != MAP_FAILED);

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

	// load each sections
	prog->text = mmap(NULL, elf_size, PROT_WRITE | PROT_EXEC,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(prog->text != MAP_FAILED);
	memcpy(prog->text, elf_img + txt_shdr->sh_offset, txt_shdr->sh_size);

	// scan symbol section (search entry point)
	int sym_entries = sym_shdr->sh_size / sym_shdr->sh_entsize;
	printf(
	    "found symbol table section: id=%d, offset=%ld, size=%ld, num=%d\n",
	    sym_idx, sym_shdr->sh_offset, sym_shdr->sh_size, sym_entries);
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
	prog->entry_off = main_sym->st_value;

	ushell_program_current_idx += 1;
	munmap(elf_img, elf_size);
}

static void ushell_program_run(char *prog_name, int argc, char *argv[])
{
	struct ushell_program *prog = ushell_program_find(prog_name);
	assert(prog);
	int (*func)(int, char *[]) = prog->text + prog->entry_off;
	int r = func(argc, argv);
	printf("return value: %d\n", r);
}

static void ushell_program_free()
{
	int i = 0;
	for (i = 0; i < ushell_program_current_idx; i++) {
		munmap(ushell_programs[i].text, ushell_programs[i].text_size);
		munmap(ushell_programs[i].data, ushell_programs[i].data_size);
		munmap(ushell_programs[i].bss, ushell_programs[i].bss_size);
		munmap(ushell_programs[i].rodata,
		       ushell_programs[i].rodata_size);
	}
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		printf("Usage: %s <prog> [option...]\n", argv[0]);
		return 0;
	}
	char *prog = argv[1];

	ushell_program_load_elf(prog);
	ushell_program_run(prog, argc - 1, argv + 1);
	ushell_program_free();

	return 0;
}

#endif // USHELL_LOADER_TEST
