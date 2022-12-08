#include "elf.h"
#include "reloc.h"

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
	void *plt;
	size_t text_size;
	size_t data_size;
	size_t bss_size;
	size_t rodata_size;
	size_t plt_size;
	uint64_t entry_off;
};

struct elf_sections {
	Elf64_Shdr *shstr;
	Elf64_Shdr *str;
	Elf64_Shdr *text;
	Elf64_Shdr *data;
	Elf64_Shdr *bss;
	Elf64_Shdr *rodata;
	Elf64_Shdr *rela_text;
	Elf64_Shdr *sym;
	int text_idx;
	int data_idx;
	int bss_idx;
	int rodata_idx;
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

int ushell_loader_test_data;

int ushell_loader_test_func(int n)
{
	return n + ushell_loader_test_data;
}

void *ushell_symbol_get(const char *symbol)
{
	void *addr = NULL;

	UK_ASSERT(symbol);

	if (!strcmp(symbol, "ushell_loader_test_func")) {
		addr = (void *)ushell_loader_test_func;
	}

	return addr;
}

/* -------------------------------------------- */

#ifdef USHELL_LOADER_TEST

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

static int elf_relocate_x86_64_pc32_plt32(struct ushell_loader_ctx *ctx,
					  Elf64_Sym *sym, Elf64_Sxword sym_addr,
					  Elf64_Rela *rel)
{
	/* NOTE: recent compiler uses R_X86_64_PLT32 instead of
	 * R_X86_64_PC32 to mark 32-bit PC-relative branches.
	 * "Linker can always reduce PLT32 relocation to PC32 if
	 * function is defined locally." cf.
	 * https://sourceware.org/git/?p=binutils-gdb.git;a=commitdiff;h=bd7ab16b4537788ad53521c45469a1bdae84ad4a;hp=80c96350467f23a54546580b3e2b67a65ec65b66
	 *
	 * R_X86_64_PC32: S + A - P
	 *     S: st_value (symbol address)
	 *     A: addend
	 *     P: the address of the memory location being
	 * relocated
	 *
	 * This relocation usually happens when
	 * - calling functions (32bit relative)
	 *   e8 xx xx xx xx : call $0x0(%rip)
	 * - accessing global variables (clang or compiling with -fPIE)
	 *   8b 05 xx xx xx xx : mov 0x0(%rip), %eax
	 */
	Elf64_Sxword reloc_addr =
	    (Elf64_Sxword)(ctx->prog->text + rel->r_offset);
	Elf64_Sxword offset = sym_addr + rel->r_addend - reloc_addr;
	Elf64_Xword abs_offset = offset > 0 ? offset : -offset;
	int sym_type = ELF64_ST_TYPE(sym->st_info);
	printf("Relocation: location: %ld, "
	       "sym position: %ld, "
	       "addend: %ld, "
	       "offset=%lx\n",
	       rel->r_offset, sym->st_value, rel->r_addend, offset);
	if (abs_offset < 0xFFFFFFFF) {
		/* if offset is within 32bit, we can directly access the symbol
		 */
		memcpy(ctx->prog->text + rel->r_offset, &offset, sizeof(int));
	} else {
		/* if not, we need to use PLT */
		if (sym_type != STT_FUNC) {
			/* This might happen when accessing global variables.
			 * clang uses R_X86_64_PC32 for accessing global
			 * variables (but not for external variables).
			 * therefore, if we failed to locate .data, .rodata,
			 * .bss and .text sections within 32bit region, then the
			 * offfseet will eceeds 32bit.
			 *
			 * (gcc uses R_X86_64_REX_GOTPCRELX)
			 */
			printf("No supported\n");
			return -1;
		}
		/*
		 * 64bit jump:
		 * jmp *(%rip+off)
		 * ff 25 00 00 00 00
		 * xx xx xx xx xx xx xx xx
		 */
		printf("text: %p\n", ctx->prog->text);
		printf("data: %p\n", ctx->prog->data);
		printf("bss: %p\n", ctx->prog->bss);
		printf("rodata: %p\n", ctx->prog->rodata);
		printf("sym_addr: %p\n", (void *)sym_addr);
		printf("reloc_addr: %p\n", (void *)reloc_addr);
		printf("Offset too large: %ld\n", offset);
	}
	return 0;
}

static Elf64_Sxword elf_get_sym_addr(struct ushell_loader_ctx *ctx,
				     Elf64_Sym *sym)
{
	int sec_idx = sym->st_shndx;
	int sym_type = ELF64_ST_TYPE(sym->st_info);
	char *sym_name = (char *)(ctx->elf_img + ctx->sections.str->sh_offset
				  + sym->st_name);
	Elf64_Sxword sym_addr = 0;
	switch (sym_type) {
	case STT_NOTYPE: {
		void *addr = ushell_symbol_get(sym_name);
		if (addr == NULL) {
			printf("Cannot resolve symbol: %s\n", sym_name);
			return -1;
		}
		printf("symaddr: %s = %p\n", sym_name, addr);
		sym_addr = (Elf64_Sxword)addr;
		break;
	}
	case STT_FUNC: {
		sym_addr = (Elf64_Sxword)(ctx->prog->text + sym->st_value);
		break;
	}
	case STT_OBJECT:
	case STT_SECTION: {
		if (sec_idx == ctx->sections.data_idx) {
			sym_addr =
			    (Elf64_Sxword)(ctx->prog->data + sym->st_value);
		} else if (sec_idx == ctx->sections.bss_idx) {
			sym_addr =
			    (Elf64_Sxword)(ctx->prog->bss + sym->st_value);
		} else if (sec_idx == ctx->sections.rodata_idx) {
			sym_addr =
			    (Elf64_Sxword)(ctx->prog->rodata + sym->st_value);
		} else {
			printf("Invalid section: %d, %s\n", sec_idx, sym_name);
			return -1;
		}
		break;
	}
	default: {
		printf("Unsupported sym type: sym_type=%d, sym_name=%s\n",
		       sym_type, sym_name);
		return -1;
	}
	}
	return sym_addr;
}

static Elf64_Sym *elf_get_sym(struct ushell_loader_ctx *ctx, int sym_idx)
{
	Elf64_Sym *sym = ctx->elf_img + ctx->sections.sym->sh_offset;
	sym += sym_idx;
	return sym;
}

static int ushell_loader_elf_relocate_symbol(struct ushell_loader_ctx *ctx)
{
	if (!ctx->sections.rela_text) {
		// no relocation entry
		return 0;
	}

	int i, ret;
	int rel_entries = ctx->sections.rela_text->sh_size
			  / ctx->sections.rela_text->sh_entsize;
	int sym_entries =
	    ctx->sections.sym->sh_size / ctx->sections.sym->sh_entsize;
	Elf64_Rela *rel = ctx->elf_img + ctx->sections.rela_text->sh_offset;

	for (i = 0; i < rel_entries; i++, rel++) {
		int sym_idx = ELF64_R_SYM(rel->r_info);
		if (sym_idx == SHN_UNDEF || sym_idx >= sym_entries) {
			printf("Unsupported relocation entry\n");
			continue;
		}
		Elf64_Sym *sym = elf_get_sym(ctx, sym_idx);
		Elf64_Sxword sym_addr = elf_get_sym_addr(ctx, sym);
		if (sym_addr <= 0) {
			return -1;
		}

		int reloc_type = ELF64_R_TYPE(rel->r_info);
		switch (reloc_type) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			ret = elf_relocate_x86_64_pc32_plt32(ctx, sym, sym_addr,
							     rel);
			if (ret != 0) {
				return -1;
			}
			break;
		default:
			printf("Unsupporeted relocation type: %d\n",
			       reloc_type);
			return -1;
		}
	}

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
	for (i = 0; i < ctx->ehdr->e_shnum; i++, shdr++) {
		char *shname = shstrtab + shdr->sh_name;
		printf("seciton %d: %s\n", i, shname);
		if (!strcmp(shname, ".text") && shdr->sh_type == SHT_PROGBITS) {
			ctx->sections.text = shdr;
			ctx->sections.text_idx = i;
		} else if (!strcmp(shname, ".data")
			   && shdr->sh_type == SHT_PROGBITS) {
			ctx->sections.data = shdr;
			ctx->sections.data_idx = i;
		} else if (!strcmp(shname, ".bss")
			   && shdr->sh_type == SHT_NOBITS) {
			ctx->sections.bss = shdr;
			ctx->sections.bss_idx = i;
		} else if (!strcmp(shname, ".rodata")
			   && shdr->sh_type == SHT_PROGBITS) {
			ctx->sections.rodata = shdr;
			ctx->sections.rodata_idx = i;
		} else if (!strcmp(shname, ".rela.text")
			   && shdr->sh_type == SHT_RELA) {
			ctx->sections.rela_text = shdr;
		} else if (!strcmp(shname, ".symtab")
			   && shdr->sh_type == SHT_SYMTAB) {
			ctx->sections.sym = shdr;
		} else if (!strcmp(shname, ".strtab")
			   && shdr->sh_type == SHT_STRTAB) {
			ctx->sections.str = shdr;
		} else if (strcmp(shname, ".rela.eh_frame") != 0
			   && (shdr->sh_type == SHT_REL
			       || shdr->sh_type == SHT_RELA)) {
			printf("!!! unsupported relocation entry: %s\n",
			       shname);
		}
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

static int mmap_and_copy_section(void **addr, size_t size, void *src)
{
	return 0;
}

static int ushell_loader_elf_load_section(struct ushell_loader_ctx *ctx)
{
#define __MAP_AND_COPY(SECTION, ADDR)                                          \
	do {                                                                   \
		if (ctx->sections.SECTION == NULL) {                           \
			break;                                                 \
		}                                                              \
		size_t size = ctx->sections.SECTION->sh_size;                  \
		if (size == 0) {                                               \
			break;                                                 \
		}                                                              \
		ctx->prog->SECTION##_size = size;                              \
		ctx->prog->SECTION =                                           \
		    mmap(ADDR, size, PROT_WRITE | PROT_EXEC | PROT_READ,       \
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);                  \
		if (ctx->prog->SECTION == MAP_FAILED) {                        \
			printf("failed to mmap text section\n");               \
			return -1;                                             \
		}                                                              \
		void *src = ctx->elf_img + ctx->sections.SECTION->sh_offset;   \
		if (!strcmp(#SECTION, "bss")) {                                \
			memset(ctx->prog->SECTION, 0, size);                   \
		} else {                                                       \
			memcpy(ctx->prog->SECTION, src, size);                 \
		}                                                              \
	} while (0)

#if 1
	__MAP_AND_COPY(text, NULL);
	__MAP_AND_COPY(data, NULL);
	__MAP_AND_COPY(bss, NULL);
	__MAP_AND_COPY(rodata, NULL);
#else
	__MAP_AND_COPY(text, (void *)0x10000);
	__MAP_AND_COPY(data, (void *)0x20000);
	__MAP_AND_COPY(bss, (void *)0x30000);
	__MAP_AND_COPY(rodata, (void *)0x40000);
#endif

#undef __MAP_AND_COPY

	return 0;
}

static Elf64_Sym *ushell_loader_elf_find_sym(struct ushell_loader_ctx *ctx,
					     char *symname)
{
	int i;
	int sym_entries =
	    ctx->sections.sym->sh_size / ctx->sections.sym->sh_entsize;
	Elf64_Sym *sym = ctx->elf_img + ctx->sections.sym->sh_offset;

	for (i = 0; i < sym_entries; i++, sym++) {
		if (sym->st_name == 0) {
			continue;
		}
		char *name =
		    (char *)(ctx->elf_img + ctx->sections.str->sh_offset
			     + sym->st_name);
		if (!strcmp(name, symname)) {
			return sym;
		}
	}
	return NULL;
}

static int ushell_loader_elf_find_entry(struct ushell_loader_ctx *ctx)
{
	Elf64_Sym *main_sym = ushell_loader_elf_find_sym(ctx, "main");

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

	r = ushell_loader_elf_relocate_symbol(&ctx);
	if (r != 0) {
		printf("failed to relocate symbols\n");
		goto err;
	}

	r = ushell_loader_elf_find_entry(&ctx);
	if (r != 0) {
		printf("failed to find main entry point\n");
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
