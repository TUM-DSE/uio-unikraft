#include "elf.h"

#include <string.h> // strncpy, memcpy, memset

#ifdef USHELL_LOADER_TEST

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#define UK_ASSERT assert
#define USHELL_LOADER_PRRINT printf
#if 1
#define USHELL_LOADER_PR_DEBUG printf
#else
#define USHELL_LOADER_PR_DEBUG(...)                                            \
	do {                                                                   \
	} while (0)
#endif
#define USHELL_LOADER_PR_ERR printf
#define USHELL_LOADER_PR_WARN printf

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
#define USHELL_LOADER_PR_WARN uk_pr_warn

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

struct elf_sections {
	Elf64_Shdr *shstr;
	Elf64_Shdr *str;
	Elf64_Shdr *text;
	Elf64_Shdr *sym;
};

struct ushell_loader_ctx {
	void *elf_img;
	size_t elf_size;
	Elf64_Ehdr *ehdr;
	struct elf_sections sections;
	struct ushell_program *prog;
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

static void ushell_program_init(struct ushell_loader_ctx *ctx, char *name)
{
	if (ushell_program_find(name) != NULL) {
		USHELL_LOADER_PR_WARN("program %s is already loaded\n", name);
	}
	memcpy(ctx->prog->name, name, USHELL_PROG_NAME_MAX);
	ctx->prog->text = NULL;
	ctx->prog->data = NULL;
	ctx->prog->bss = NULL;
	ctx->prog->rodata = NULL;
	ctx->prog->text_size = 0;
	ctx->prog->data_size = 0;
	ctx->prog->bss_size = 0;
	ctx->prog->rodata_size = 0;
	ctx->prog->entry_off = 0;
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

static void ushell_program_free(int idx)
{
	assert(idx < USHELL_PROG_MAX_NUM);
	struct ushell_program *prog = &ushell_programs[idx];
	munmap(prog->text, prog->text_size);
	munmap(prog->data, prog->data_size);
	munmap(prog->bss, prog->bss_size);
	munmap(prog->rodata, prog->rodata_size);
	memset(prog, 0, sizeof(struct ushell_program));
}

static void ushell_program_free_all()
{
	int i;
	for (i = 0; i < ushell_program_current_idx; i++) {
		ushell_program_free(i);
	}
}

static void dump_text(struct ushell_program *prog)
{
	size_t i;
	char *p = prog->text;
	printf("text size: %ld\n", prog->text_size);
	for (i = 0; i < prog->text_size; i++) {
		printf("%02X ", *p++ & 0xFF);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

static int ushell_loader_elf_relocate_symbol(struct ushell_loader_ctx *ctx)
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
	return 0;
}

static void ushell_loader_map_elf_image(struct ushell_loader_ctx *ctx,
					char *path)
{
	int fd = open(path, O_RDONLY);
	assert(fd > 0);
	struct stat sb;
	fstat(fd, &sb);

	printf("file: %s, size: %ld\n", path, sb.st_size);
	ctx->elf_size = sb.st_size;
	ctx->elf_img = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(ctx->elf_img != MAP_FAILED);
	ctx->ehdr = ctx->elf_img;
}

static int ushell_loader_check_elf_header(struct ushell_loader_ctx *ctx)
{
	Elf64_Ehdr *ehdr = ctx->ehdr;
	if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
	    || ehdr->e_ident[2] != 'L' && ehdr->e_ident[3] != 'F') {
		printf("Invalid elf magic number\n");
		return -1;
	}
	if (ehdr->e_machine != EM_AMD64) {
		printf("Unsupported elf machine: %d\n", ehdr->e_machine);
		return -1;
	}
	if (ehdr->e_type != ET_REL) {
		printf("Unsupported elf type: %d\n", ehdr->e_type);
		return -1;
	}
	return 0;
}

static int ushell_loader_elf_scan_section(struct ushell_loader_ctx *ctx)
{
	printf("section num: %d\n", ctx->ehdr->e_shnum);
	printf("string table idx: %d\n", ctx->ehdr->e_shstrndx);
	Elf64_Shdr *shdr = ctx->elf_img + ctx->ehdr->e_shoff;
	ctx->sections.shstr = shdr + ctx->ehdr->e_shstrndx;
	char *shstrtab = ctx->elf_img + ctx->sections.shstr->sh_offset;
	int i;
	for (i = 0; i < ctx->ehdr->e_shnum; i++) {
		char *shname = shstrtab + shdr->sh_name;
		printf("seciton %d: %s\n", i, shname);
		if (!strcmp(shname, ".text")) {
			ctx->sections.text = shdr;
		} else if (!strcmp(shname, ".symtab")) {
			ctx->sections.sym = shdr;
		} else if (!strcmp(shname, ".strtab")) {
			ctx->sections.str = shdr;
		}
		shdr++;
	}

	if (ctx->sections.text == NULL) {
		printf("could not find .text section\n");
		return -1;
	}
	if (ctx->sections.sym == NULL) {
		printf("could not find .symtab section\n");
		return -1;
	}
	if (ctx->sections.str == NULL) {
		printf("could not find .strtab section\n");
		return -1;
	}
	return 0;
}

static int ushell_loader_elf_load_section(struct ushell_loader_ctx *ctx)
{
	ctx->prog->text_size = ctx->sections.text->sh_size;
	ctx->prog->text =
	    mmap(NULL, ctx->prog->text_size, PROT_WRITE | PROT_EXEC,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ctx->prog->text == MAP_FAILED) {
		printf("failed to mmap text section\n");
		ctx->prog->text = NULL;
		ctx->prog->text_size = 0;
		return -1;
	}
	memcpy(ctx->prog->text, ctx->elf_img + ctx->sections.text->sh_offset,
	       ctx->sections.text->sh_size);
	return 0;
}

static int ushell_loader_elf_scan_symbol(struct ushell_loader_ctx *ctx)
{
	int i;
	int sym_entries =
	    ctx->sections.sym->sh_size / ctx->sections.sym->sh_entsize;
	Elf64_Sym *sym = ctx->elf_img + ctx->sections.sym->sh_offset;
	Elf64_Sym *main_sym = NULL;

	for (i = 0; i < sym_entries; i++, sym++) {
		char *name =
		    sym->st_name == 0
			? "<noname>"
			: (char *)(ctx->elf_img + ctx->sections.str->sh_offset
				   + sym->st_name);
		printf(
		    "symbol %d: %s, size=%ld, value=%ld, type=%d, shndx=%x\n",
		    i, name, sym->st_size, sym->st_value, sym->st_info & 0xf,
		    sym->st_shndx);
		if (!strncmp(name, "main", 4)) {
			main_sym = sym;
		}
	}

	if (main_sym == NULL) {
		printf("no main symbol\n");
		return -1;
	}

	ctx->prog->entry_off = main_sym->st_value;

	return 0;
}

static int ushell_loader_load_elf(char *path)
{
	int ret = 0, r;
	if (ushell_program_current_idx >= USHELL_PROG_MAX_NUM) {
		printf("reach program loading limit\n");
		return -1;
	}

	struct ushell_loader_ctx ctx = {};

	ctx.prog = &ushell_programs[ushell_program_current_idx];
	ushell_program_current_idx += 1;
	ushell_program_init(&ctx, path);

	ushell_loader_map_elf_image(&ctx, path);

	r = ushell_loader_check_elf_header(&ctx);
	if (r != 0) {
		printf("invalid program binary\n");
		goto err;
	}

	r = ushell_loader_elf_scan_section(&ctx);
	if (r != 0) {
		printf("failed to scan sections\n");
		goto err;
	}

	r = ushell_loader_elf_load_section(&ctx);
	if (r != 0) {
		printf("failed to load sections\n");
		goto err;
	}

	r = ushell_loader_elf_scan_symbol(&ctx);
	if (r != 0) {
		printf("failed to scan symbols\n");
		goto err;
	}

	r = ushell_loader_elf_relocate_symbol(&ctx);
	if (r != 0) {
		printf("failed to relocate symbols\n");
		goto err;
	}

end:
	munmap(ctx.elf_img, ctx.elf_size);
	return ret;

err:
	ushell_program_current_idx -= 1;
	ushell_program_free(ushell_program_current_idx);
	ret = -1;
	goto end;
}

static void ushell_program_run(char *prog_name, int argc, char *argv[])
{
	struct ushell_program *prog = ushell_program_find(prog_name);
	if (!prog) {
		printf("program not found: %s\n", prog_name);
		return;
	}
	dump_text(prog);
	int (*func)(int, char *[]) = prog->text + prog->entry_off;
	int r = func(argc, argv);
	printf("return value: %d\n", r);
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		printf("Usage: %s <prog> [args...]\n", argv[0]);
		return 0;
	}
	char *prog = argv[1];

	int r = ushell_loader_load_elf(prog);
	assert(r == 0);
	ushell_program_run(prog, argc - 1, argv + 1);
	ushell_program_free_all();

	return 0;
}

#endif // USHELL_LOADER_TEST
