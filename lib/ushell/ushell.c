#include "uk/plat/paging.h"
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/print.h>
#include <uk/hexdump.h>
#include <vfscore/mount.h>

#include <ushell/ushell.h>

#include <string.h>
#include <stdio.h>

#define BUFSIZE 128

static void ushell_puts_n(char *str, size_t len)
{
	uk_console_puts(str, len);
}

static void ushell_puts(char *str)
{
	size_t len = strlen(str);
	ushell_puts_n(str, len);
}

static void ushell_print_prompt()
{
	ushell_puts("> ");
}

static void ushell_gets(char *buf, unsigned size)
{
	char ch;
	unsigned i = 0;

	while (1) {
		ch = uk_console_getc();
		buf[i] = ch;
		if (ch == '\n' || ch == '\0') {
			buf[i] = '\0'; // remove new line
			break;
		}
		i++;
		if (i == size - 1) {
			uk_pr_err("ushell: buffer full\n");
			break;
		}
	}
	buf[i] = '\0';
}

char *strip_str(char *str)
{
	char *p = str;
	while (*p != '\0' && (*p == ' ' || *p == '\n')) {
		p++;
	}
	return p;
}

static void ushell_listdir(int argc, char *argv[])
{
	DIR *dp;
	struct dirent *ent;
	char buf[128];
	char *path;
	if (argc >= 2) {
		path = argv[1];
	} else {
		path = "/";
	}
	dp = opendir(path);
	if (!dp) {
		snprintf(buf, sizeof(buf), "No such directory: %s\n", path);
		ushell_puts(buf);
		return;
	}
	while ((ent = readdir(dp))) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		snprintf(buf, sizeof(buf), "%s\n", ent->d_name);
		ushell_puts(buf);
	}
	closedir(dp);
}

#ifdef CONFIG_HAVE_LIBC
static void ushell_cat(int argc, char *argv[])
{
	FILE *fp;
	char buf[128];

	if (argc <= 1) {
		ushell_puts("Usage: cat [file]\n");
		return;
	}

	fp = fopen(argv[1], "rt");
	if (fp == NULL) {
		snprintf(buf, sizeof(buf), "Error opening file %s", argv[1]);
		ushell_puts(buf);
	}
	while (fgets(buf, 128, fp) != NULL) {
		ushell_puts(buf);
	}
	fclose(fp);
}

#include <sys/mman.h>

static void ushell_run(int argc, char *argv[])
{
	FILE *fp;
	char buf[128];
	char *cmd;
	void *code;
	int r;
	unsigned size, pages;
	UK_ASSERT(argc >= 0);
	if (argc == 0 || argv[0][0] == '\0') {
		ushell_puts("Usage: run <cmd> [args]\n");
		return;
	}
	cmd = argv[0];

	// open file
	fp = fopen(cmd, "rt");
	if (fp == NULL) {
		snprintf(buf, sizeof(buf), "Error opening file %s", argv[1]);
		ushell_puts(buf);
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	pages = (size + PAGE_SIZE) / PAGE_SIZE;
	fseek(fp, 0, SEEK_SET);

// #define USE_MMAP
#ifdef USE_MMAP
	code = mmap(NULL, size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON,
		    -1, 0);
	if (code == MAP_FAILED || code == 0) {
		uk_pr_info("ushell: mmap failed: code=%ld\n", (long)code);
		ushell_puts("Failed to run command\n");
		return;
	}
	uk_pr_info("ushell: mmap addr=%#lx\n", (long)code);
#else
	struct uk_pagetable *pt = ukplat_pt_get_active();
	// FIXME: find proper vaddr
	code = (void *)0x80000000;
	int rc = ukplat_page_map(pt, (long long)code, __PADDR_ANY, pages,
				 PAGE_ATTR_PROT_WRITE | PAGE_ATTR_PROT_EXEC, 0);
	UK_ASSERT(rc == 0);
#endif

	fread(code, size, 1, fp);
	fclose(fp);
	uk_pr_info("ushell: load\n");
#if 0
	uk_hexdumpC(code, size);
#endif

	// run
	{
		int (*func)(int, char *[]) = code;
		r = func(argc, argv);
		snprintf(buf, sizeof(buf), "%d\n", r);
		ushell_puts(buf);
	}

#ifdef _USE_MMAP
	munmap(code, size);
#else
	ukplat_page_unmap(pt, (long long)code, pages, 0);
#endif
}

#endif /* CONFIG_HAVE_LIBC */

static int ushell_process_cmd(int argc, char *argv[])
{
	UK_ASSERT(argc >= 1);
	char *cmd = argv[0];
	if (*cmd == '\0') {
		return 0;
	} else if (!strcmp(cmd, "ls")) {
		ushell_listdir(argc, argv);
#ifdef CONFIG_HAVE_LIBC
	} else if (!strcmp(cmd, "run")) {
		ushell_run(argc - 1, argv + 1);
	} else if (!strcmp(cmd, "cat")) {
		ushell_cat(argc, argv);
#endif
	} else if (!strcmp(cmd, "quit")) {
		ushell_puts("bye\n");
		return 1;
	} else {
		ushell_puts("Error: unknown command\n");
	}
	return 0;
}

static int ushell_mount()
{
	const char *rootdev = "fs0";
	const char *rootfs = "9pfs";
	int rootflags = 0;
	const char *rootopts = "";

	uk_pr_info("ushell: mount fs to / \n");
	if (mount(rootdev, "/", rootfs, rootflags, rootopts) != 0) {
		uk_pr_crit("Failed to mount %s (%s) at /\n", rootdev, rootfs);
		return -1;
	}

	return 0;
}

#define USHELL_MAX_ARGS 16

static int ushell_split_args(char *buf, char *args[])
{
	char *p = buf;
	int i = 0;
	args[0] = p;
	while (1) {
		p = strip_str(p);
		args[i++] = p;
		while (*p != ' ' && *p != '\0' && *p != '\n') {
			p++;
		}
		if (*p == '\0') {
			break;
		}
		*p++ = '\0';
		if (i >= USHELL_MAX_ARGS) {
			// FIXME
			uk_pr_err("ushell: too many args: %s\n", buf);
			break;
		}
	}
	return i;
}

void ushell_spawn_shell()
{
	int argc, rc;
	char buf[BUFSIZE];
	char *argv[USHELL_MAX_ARGS];

	uk_pr_info("ushell spawn\n");

	rc = ushell_mount();

	if (rc < 0) {
		return;
	}

	while (1) {
		ushell_print_prompt();
		ushell_gets(&buf[0], BUFSIZE);
		argc = ushell_split_args(buf, argv);
		rc = ushell_process_cmd(argc, argv);
		if (rc) {
			break;
		}
	}
}
