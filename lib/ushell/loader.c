#include "elf.h"
#include "reloc.h"

#include <string.h> // strncpy, memcpy, memset, memcmp

#ifdef USHELL_LOADER_TEST
/* To test the loader
 * cc -DUSHELL_LOADER_TEST -o loader loader.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#define USHELL_ASSERT assert
#define USHELL_PRINTF printf
#if 1
#define USHELL_PR_DEBUG printf
#else
#define USHELL_PR_DEBUG(...)                                                   \
	do {                                                                   \
	} while (0)
#endif
#define USHELL_PR_ERR printf
#define USHELL_PR_WARN printf
#define USHELL_MAP_FAILED MAP_FAILED

void *ushell_alloc_memory(unsigned long size)
{
	return mmap(NULL, size, PROT_WRITE | PROT_EXEC | PROT_READ,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void ushell_free_memory(void *addr, unsigned long size)
{
	munmap(addr, size);
}

#else // USHELL_LOADER_TEST

#include <stdio.h>
#include <uk/assert.h>
#include <uk/print.h>

#include "ushell_api.h"

#define USHELL_ASSERT UK_ASSERT
#define USHELL_PRINTF uk_pr_info
#define USHELL_PR_DEBUG uk_pr_debug
#define USHELL_PR_ERR uk_pr_err
#define USHELL_PR_WARN uk_pr_warn
#define USHELL_MAP_FAILED (void *)-1

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
	void *got;
	size_t text_size;
	size_t data_size;
	size_t bss_size;
	size_t rodata_size;
	size_t plt_size;
	size_t got_size;
	int plt_idx;
	int got_idx;
	uint64_t entry_off;
};

struct plt_entry {
	char insn[6];
	char addr[8];
	char pad[2];
} __attribute__((packed));

struct got_entry {
	uint64_t addr;
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
		USHELL_PR_WARN("program %s is already loaded\n", name);
	}
	memset(ctx->prog, 0, sizeof(struct ushell_program));
	memcpy(ctx->prog->name, name, USHELL_PROG_NAME_MAX);
}

int ushell_loader_test_data;

int ushell_loader_test_func(int n)
{
	return n + ushell_loader_test_data;
}

void *ushell_symbol_get(const char *symbol)
{
	void *addr = NULL;

	USHELL_ASSERT(symbol);

	if (!strcmp(symbol, "ushell_loader_test_func")) {
		addr = (void *)ushell_loader_test_func;
	} else if (!strcmp(symbol, "ushell_loader_test_data")) {
		addr = (void *)&ushell_loader_test_data;
	}

	return addr;
}

static void ushell_program_free(int idx)
{
	USHELL_ASSERT(idx < USHELL_PROG_MAX_NUM);
	struct ushell_program *prog = &ushell_programs[idx];
	ushell_free_memory(prog->text, prog->text_size);
	ushell_free_memory(prog->data, prog->data_size);
	ushell_free_memory(prog->bss, prog->bss_size);
	ushell_free_memory(prog->rodata, prog->rodata_size);
	ushell_free_memory(prog->plt, prog->plt_size);
	ushell_free_memory(prog->got, prog->got_size);
	memset(prog, 0, sizeof(struct ushell_program));
}

void ushell_program_free_all()
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
	USHELL_PRINTF("text size: %ld\n", prog->text_size);
	for (i = 0; i < prog->text_size; i++) {
		USHELL_PRINTF("%02X ", *p++ & 0xFF);
		if ((i + 1) % 16 == 0) {
			USHELL_PRINTF("\n");
		}
	}
	USHELL_PRINTF("\n");
}

static struct plt_entry *search_plt(struct ushell_loader_ctx *ctx,
				    Elf64_Sxword addr)
{
	int i;
	struct plt_entry *p = ctx->prog->plt;

	for (i = 0; i < ctx->prog->plt_idx; i++, p++) {
		if (!memcmp(&p->addr[0], &addr, sizeof(addr))) {
			USHELL_PR_DEBUG("ushell: plt: find %d\n", i);
			return p;
		}
	}

	return NULL;
}

static struct got_entry *search_got(struct ushell_loader_ctx *ctx,
				    Elf64_Sxword addr)
{
	int i;
	struct got_entry *p = ctx->prog->got;

	for (i = 0; i < ctx->prog->got_idx; i++, p++) {
		if (!memcmp(&p->addr, &addr, sizeof(addr))) {
			USHELL_PR_DEBUG("ushell: got: find %d\n", i);
			return p;
		}
	}

	return NULL;
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
	 * This relocation happens when
	 * - calling functions (32bit relative)
	 *   e8 xx xx xx xx : call $0x0(%rip)
	 * - accessing global variables (clang or compiling with -fPIE)
	 *   8b 05 xx xx xx xx : mov 0x0(%rip), %eax
	 */
	Elf64_Sxword reloc_addr =
	    (Elf64_Sxword)((char *)ctx->prog->text + rel->r_offset);
	Elf64_Sxword offset = sym_addr + rel->r_addend - reloc_addr;
	Elf64_Xword abs_offset = offset > 0 ? offset : -offset;
	int sym_type = ELF64_ST_TYPE(sym->st_info);
	USHELL_PR_DEBUG("Relocation: location: %ld, "
			"sym position: %ld, "
			"addend: %ld, "
			"offset=%lx\n",
			rel->r_offset, sym->st_value, rel->r_addend, offset);
	if (abs_offset <= 0xFFFFFFFF) {
		/* if offset is within 32bit, we can directly access the symbol
		 */
		memcpy((char *)ctx->prog->text + rel->r_offset, &offset,
		       sizeof(int));
	} else {
		/* if not, we need to use PLT */
		if (sym_type == STT_OBJECT) {
			/* This might happen when accessing global variables.
			 * clang uses R_X86_64_PC32 for accessing global
			 * variables (but not for external variables) if mcmodel
			 * is default. Therefore, if we failed to locate .data,
			 * .rodata, .bss and .text sections within 32bit region,
			 * then the offfseet might eceed 32bit.
			 *
			 * (gcc uses R_X86_64_REX_GOTPCRELX)
			 */
			USHELL_PR_ERR(
			    "ushell: Cannot relocate symbol object with 64bit "
			    "offset\n");
			return -1;
		}
		/*
		 * generate jump code in PLT
		 * we don't use GOT but use relative jmp here: jump with the
		 * address stored immediately after the instruction
		 *
		 * jmp *0x0(%rip)
		 * ff 25 00 00 00 00 xx xx xx xx xx xx xx xx (14 bytes)
		 *
		 * One PLT entry uses 16 bytes (the last 2 bytes are unused)
		 *
		 */

#define USHELL_LOADER_PLT_SIZE 4096

		if (!ctx->prog->plt) {
			ctx->prog->plt =
			    ushell_alloc_memory(USHELL_LOADER_PLT_SIZE);
			if (ctx->prog->plt == USHELL_MAP_FAILED) {
				USHELL_PR_ERR("ushell: failed to map plt\n");
				return -1;
			}
			ctx->prog->plt_size = USHELL_LOADER_PLT_SIZE;
			ctx->prog->plt_idx = 0;
		}

		struct plt_entry *plt_entry = search_plt(ctx, sym_addr);
		if (plt_entry) {
			Elf64_Sxword plt_offset = (Elf64_Sxword)plt_entry
						  + rel->r_addend - reloc_addr;
			memcpy((char *)ctx->prog->text + rel->r_offset,
			       &plt_offset, sizeof(int));
			return 0;
		}

		int plt_max_size = ctx->prog->plt_size / sizeof(struct plt_entry);
		if (ctx->prog->plt_idx >= plt_max_size) {
			USHELL_PR_ERR("ushell: Too many entry\n");
			// TODO: realloc plt
			return -1;
		}

		USHELL_PR_DEBUG("ushell: use plt %d\n", ctx->prog->plt_idx);

		plt_entry =
		    (struct plt_entry *)ctx->prog->plt + ctx->prog->plt_idx;
		char code[16] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				 0x00, 0x00, 0xcc, 0xcc};

		/* set symbol address in PLT */
		memcpy(&code[6], &sym_addr, 8);
		memcpy(plt_entry, code, sizeof(code));

		/* set relative jmp to PLT */
		Elf64_Sxword plt_offset =
		    (Elf64_Sxword)plt_entry + rel->r_addend - reloc_addr;
		Elf64_Xword abs_plt_offset =
		    plt_offset > 0 ? plt_offset : -plt_offset;
		if (abs_plt_offset > 0xFFFFFFFF) {
			/* FIXME: we failed to locate PLT within 32bit region
			 * relative to .text
			 */
			USHELL_PR_ERR("ushell: plt offset too large\n");
			return -1;
		}
		memcpy((char *)ctx->prog->text + rel->r_offset, &plt_offset,
		       sizeof(int));
		ctx->prog->plt_idx += 1;
	}
	return 0;
}

static int elf_relocate_x86_64_gotpcrel(struct ushell_loader_ctx *ctx,
					Elf64_Sym *sym __attribute__((unused)), Elf64_Sxword sym_addr,
					Elf64_Rela *rel)
{

	/*
	 * From SYSV AMD64 ABI documentation:
	 *
	 * """
	 * The R_X86_64_GOTPCREL relocation has different semantics from the
	 * R_X86_64_GOT32 or equivalent i386 R_386_GOTPC relocation. In
	 * particular, because the AMD64 architecture has an addressing mode
	 * relative to the instruction pointer, it is possible to load an
	 * address from the GOT using a single instruction. The calculation done
	 * by the R_X86_64_GOTPCREL relocation gives the difference between the
	 * location in the GOT where the symbol’s address is given and the
	 * location where the relocation is applied.
	 * For the occurrence of name@GOTPCREL in the following assembler
	 * instructions:
	 *
	 *         call       *name@GOTPCREL(%rip)
	 *         jmp        *name@GOTPCREL(%rip)
	 *         mov        name@GOTPCREL(%rip), %reg
	 *         test       %reg, name@GOTPCREL(%rip)
	 *         binop      name@GOTPCREL(%rip), %reg
	 *
	 * where binop is one of adc, add, and, cmp, or, sbb, sub, xor
	 * instructions, the R_X86_64_GOTPCRELX relocation, or the
	 * R_X86_64_REX_GOTPCRELX relocation if the REX prefix is present,
	 * should be generated, instead of the R_X86_64_GOTPCREL relocation.
	 * """
	 *
	 * Apparently GOTPCRELX is used for optimization. Here we treat all of
	 * them in the same way.
	 *
	 * R_X86_64_GOTPCREL: G + GOT + A - P
	 *     G: the offset into the GOT
	 *   GOT: the address of the GOT
	 *     A: addend
	 *     P: the address of the memory location being relocated
	 *
	 * This relocation happens when
	 * - accessing an extern variable
	 *   48 8b 05 xx xx xx xx    mov    0x0(%rip),%rax # load addr from GOT
	 *   8b 00                   mov    (%rax),%eax    # load the value
	 */

#define USHELL_LOADER_GOT_SIZE 4096

	if (!ctx->prog->got) {
		ctx->prog->got = ushell_alloc_memory(USHELL_LOADER_GOT_SIZE);
		if (ctx->prog->got == USHELL_MAP_FAILED) {
			USHELL_PR_ERR("ushell: failed to map plt\n");
			return -1;
		}
		ctx->prog->got_size = USHELL_LOADER_GOT_SIZE;
		ctx->prog->got_idx = 0;
	}

	Elf64_Sxword reloc_addr =
	    (Elf64_Sxword)(ctx->prog->text + rel->r_offset);
	struct got_entry *got_entry = search_got(ctx, sym_addr);
	if (got_entry) {
		Elf64_Sxword got_offset =
		    (Elf64_Sxword)got_entry + rel->r_addend - reloc_addr;
		memcpy((char *)ctx->prog->text + rel->r_offset, &got_offset,
		       sizeof(int));
		return 0;
	}

	int max_got_size = ctx->prog->got_size / sizeof(struct got_entry);
	if (ctx->prog->got_idx >= max_got_size) {
		USHELL_PR_ERR("ushell: Too many entry\n");
		// TODO: realloc got
		return -1;
	}

	USHELL_PR_DEBUG("ushell: use got %d\n", ctx->prog->got_idx);
	got_entry = (struct got_entry *)ctx->prog->got + ctx->prog->got_idx;
	memcpy(got_entry, &sym_addr, sizeof(sym_addr));
	Elf64_Sxword offset =
	    (Elf64_Sxword)got_entry + rel->r_addend - reloc_addr;
	Elf64_Xword abs_offset = offset > 0 ? offset : -offset;
	if (abs_offset > 0xFFFFFFFF) {
		/* FIXME: we failed to locate GOT within 32bit region
		 * relative to .text
		 */
		USHELL_PR_ERR("ushell: got offset too large\n");
		return -1;
	}
	memcpy((char *)ctx->prog->text + rel->r_offset, &offset, sizeof(int));

	ctx->prog->got_idx += 1;
	return 0;
}

static Elf64_Sxword elf_get_sym_addr(struct ushell_loader_ctx *ctx,
				     Elf64_Sym *sym)
{
	int sec_idx = sym->st_shndx;
	int sym_type = ELF64_ST_TYPE(sym->st_info);
	char *sym_name = (char *)ctx->elf_img
			 + (ctx->sections.str->sh_offset + sym->st_name);
	Elf64_Sxword sym_addr = 0;
	switch (sym_type) {
	case STT_NOTYPE: {
		void *addr = ushell_symbol_get(sym_name);
		if (addr == NULL) {
			USHELL_PR_ERR("ushell: Cannot resolve symbol: %s\n",
				      sym_name);
			return -1;
		}
		USHELL_PR_DEBUG("ushell: symaddr: %s = %p\n", sym_name, addr);
		sym_addr = (Elf64_Sxword)addr;
		break;
	}
	case STT_FUNC: {
		sym_addr =
		    (Elf64_Sxword)((char *)ctx->prog->text + sym->st_value);
		break;
	}
	case STT_OBJECT:
	case STT_SECTION: {
		if (sec_idx == ctx->sections.data_idx) {
			sym_addr = (Elf64_Sxword)((char *)ctx->prog->data
						  + sym->st_value);
		} else if (sec_idx == ctx->sections.bss_idx) {
			sym_addr = (Elf64_Sxword)((char *)ctx->prog->bss
						  + sym->st_value);
		} else if (sec_idx == ctx->sections.rodata_idx) {
			sym_addr = (Elf64_Sxword)((char *)ctx->prog->rodata
						  + sym->st_value);
		} else {
			USHELL_PR_ERR("ushell: Invalid section: %d, %s\n",
				      sec_idx, sym_name);
			return -1;
		}
		break;
	}
	default: {
		USHELL_PR_ERR(
		    "ushell: Unsupported sym type: sym_type=%d, sym_name=%s\n",
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
		/* no relocation entry */
		return 0;
	}

	int i, ret;
	int rel_entries = ctx->sections.rela_text->sh_size
			  / ctx->sections.rela_text->sh_entsize;
	int sym_entries =
	    ctx->sections.sym->sh_size / ctx->sections.sym->sh_entsize;
	Elf64_Rela *rel =
	    (void *)((char *)ctx->elf_img + ctx->sections.rela_text->sh_offset);

	for (i = 0; i < rel_entries; i++, rel++) {
		int sym_idx = ELF64_R_SYM(rel->r_info);
		if (sym_idx == SHN_UNDEF || sym_idx >= sym_entries) {
			USHELL_PR_ERR("ushell: Unsupported relocation entry\n");
			continue;
		}
		Elf64_Sym *sym = elf_get_sym(ctx, sym_idx);
		Elf64_Sxword sym_addr = elf_get_sym_addr(ctx, sym);
		if (sym_addr <= 0) {
			return -1;
		}

		int reloc_type = ELF64_R_TYPE(rel->r_info);
		ret = 0;
		switch (reloc_type) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			ret = elf_relocate_x86_64_pc32_plt32(ctx, sym, sym_addr,
							     rel);
			break;
		case R_X86_64_GOTPCREL:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_REX_GOTPCRELX:
			ret = elf_relocate_x86_64_gotpcrel(ctx, sym, sym_addr,
							   rel);
			break;
		default:
			USHELL_PR_ERR(
			    "ushell: Unsupporeted relocation type: %d\n",
			    reloc_type);
			ret = -1;
		}
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}

/* Load a file into memory
 */
static int ushell_loader_map_elf_image(struct ushell_loader_ctx *ctx,
					char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) {
		USHELL_PR_ERR("cannot open file: %s\n", path);
		return -1;
	}
	unsigned size;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	USHELL_PR_DEBUG("ushell: file: %s, size: %d\n", path, size);
	ctx->elf_size = size;
	ctx->elf_img = ushell_alloc_memory(size);
	USHELL_ASSERT(ctx->elf_img != USHELL_MAP_FAILED);
	size_t r = fread(ctx->elf_img, size, 1, fp);
	if (r != 1){
		USHELL_PR_ERR("ushell: failed to read file\n");
		return -1;
	}
	fclose(fp);
	ctx->ehdr = ctx->elf_img;
	return 0;
}

/* Check if the loaded elf binary is supported elf binary
 */
static int ushell_loader_check_elf_header(struct ushell_loader_ctx *ctx)
{
	Elf64_Ehdr *ehdr = ctx->ehdr;
	if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
	    || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
		USHELL_PR_ERR("ushell: Invalid elf magic number\n");
		return -1;
	}
	if (ehdr->e_machine != EM_AMD64) {
		USHELL_PR_ERR("ushell: Unsupported elf machine: %d\n",
			      ehdr->e_machine);
		return -1;
	}
	if (ehdr->e_type != ET_REL) {
		USHELL_PR_ERR("ushell: Unsupported elf type: %d\n",
			      ehdr->e_type);
		return -1;
	}
	return 0;
}

/* Scan elf sections and search main sections
 */
static int ushell_loader_elf_scan_section(struct ushell_loader_ctx *ctx)
{
	USHELL_PR_DEBUG("ushell: section num: %d\n", ctx->ehdr->e_shnum);
	USHELL_PR_DEBUG("ushell: string table idx: %d\n",
			ctx->ehdr->e_shstrndx);
	Elf64_Shdr *shdr = (void *)((char *)ctx->elf_img + ctx->ehdr->e_shoff);
	ctx->sections.shstr = shdr + ctx->ehdr->e_shstrndx;
	char *shstrtab =
	    (void *)((char *)ctx->elf_img + ctx->sections.shstr->sh_offset);
	int i;
	for (i = 0; i < ctx->ehdr->e_shnum; i++, shdr++) {
		char *shname = shstrtab + shdr->sh_name;
		USHELL_PR_DEBUG("ushell: seciton %d: %s\n", i, shname);
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
			USHELL_PR_ERR(
			    "ushell: unsupported relocation entry: %s\n",
			    shname);
		}
	}

	if (ctx->sections.text == NULL) {
		USHELL_PR_ERR("ushell: could not find .text section\n");
		return -1;
	}
	if (ctx->sections.sym == NULL) {
		USHELL_PR_ERR("ushell: could not find .symtab section\n");
		return -1;
	}
	if (ctx->sections.str == NULL) {
		USHELL_PR_ERR("ushell: could not find .strtab section\n");
		return -1;
	}
	return 0;
}

/* Load elf sections into memory
 */
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
		ctx->prog->SECTION = ushell_alloc_memory(size);                \
		if (ctx->prog->SECTION == USHELL_MAP_FAILED) {                 \
			USHELL_PR_ERR("failed to map text section\n");         \
			return -1;                                             \
		}                                                              \
		void *src = (void *)((char *)ctx->elf_img                      \
				     + ctx->sections.SECTION->sh_offset);      \
		if (!strcmp(#SECTION, "bss")) {                                \
			memset(ctx->prog->SECTION, 0, size);                   \
		} else {                                                       \
			memcpy(ctx->prog->SECTION, src, size);                 \
		}                                                              \
	} while (0)

	__MAP_AND_COPY(text, NULL);
	__MAP_AND_COPY(data, NULL);
	__MAP_AND_COPY(bss, NULL);
	__MAP_AND_COPY(rodata, NULL);

#undef __MAP_AND_COPY

	return 0;
}

static Elf64_Sym *ushell_loader_elf_find_sym(struct ushell_loader_ctx *ctx,
					     char *symname)
{
	int i;
	int sym_entries =
	    ctx->sections.sym->sh_size / ctx->sections.sym->sh_entsize;
	Elf64_Sym *sym =
	    (void *)((char *)ctx->elf_img + ctx->sections.sym->sh_offset);

	for (i = 0; i < sym_entries; i++, sym++) {
		if (sym->st_name == 0) {
			continue;
		}
		char *name = (char *)(ctx->elf_img)
			     + (ctx->sections.str->sh_offset + sym->st_name);
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
		USHELL_PR_ERR("ushell: no main symbol\n");
		return -1;
	}

	ctx->prog->entry_off = main_sym->st_value;

	return 0;
}

int ushell_loader_load_elf(char *path)
{
	int ret = 0, r;
	if (ushell_program_current_idx >= USHELL_PROG_MAX_NUM) {
		USHELL_PR_ERR("ushell: reach program loading limit\n");
		return -1;
	}

	struct ushell_loader_ctx ctx = {};

	ctx.prog = &ushell_programs[ushell_program_current_idx];
	ushell_program_current_idx += 1;
	ushell_program_init(&ctx, path);

	r = ushell_loader_map_elf_image(&ctx, path);
	if (r != 0) {
		USHELL_PR_ERR("ushell: failed to load file\n");
		goto err;
	}

	r = ushell_loader_check_elf_header(&ctx);
	if (r != 0) {
		USHELL_PR_ERR("ushell: invalid program binary\n");
		goto err;
	}

	r = ushell_loader_elf_scan_section(&ctx);
	if (r != 0) {
		USHELL_PR_ERR("ushell: failed to scan sections\n");
		goto err;
	}

	r = ushell_loader_elf_load_section(&ctx);
	if (r != 0) {
		USHELL_PR_ERR("ushell: failed to load sections\n");
		goto err;
	}

	r = ushell_loader_elf_relocate_symbol(&ctx);
	if (r != 0) {
		USHELL_PR_ERR("ushell: failed to relocate symbols\n");
		goto err;
	}

	r = ushell_loader_elf_find_entry(&ctx);
	if (r != 0) {
		USHELL_PR_ERR("ushell: failed to find main entry point\n");
		goto err;
	}

end:
	ushell_free_memory(ctx.elf_img, ctx.elf_size);
	return ret;

err:
	ushell_program_current_idx -= 1;
	ushell_program_free(ushell_program_current_idx);
	ret = -1;
	goto end;
}

int ushell_program_run(char *prog_name, int argc, char *argv[],
			      int *retval)
{
	struct ushell_program *prog = ushell_program_find(prog_name);
	if (!prog) {
		USHELL_PR_ERR("ushell: program not found: %s\n", prog_name);
		return -1;
	}
#if 0
	dump_text(prog);
#endif
	USHELL_PR_DEBUG("ushell: program run: %s\n", prog_name);
	int (*func)(int, char *[]) =
	    (void *)((char *)prog->text + prog->entry_off);
	int r = func(argc, argv);
	USHELL_PR_DEBUG("ushell: return value: %d\n", r);
	if (retval) {
		*retval = r;
	}
	return 0;
}

/* -------------------------------------------- */

#ifdef USHELL_LOADER_TEST

int main(int argc, char *argv[])
{
	if (argc == 1) {
		USHELL_PRINTF("Usage: %s <prog> [args...]\n", argv[0]);
		return 0;
	}
	char *prog = argv[1];

	int r = ushell_loader_load_elf(prog);
	USHELL_ASSERT(r == 0);
	ushell_program_run(prog, argc - 1, argv + 1, NULL);
	ushell_program_free_all();

	return 0;
}

#endif // USHELL_LOADER_TEST
