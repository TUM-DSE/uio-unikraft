#include "uk/plat/paging.h"
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/print.h>
#include <uk/hexdump.h>
#include <vfscore/mount.h>

#if CONFIG_LIBUKSCHED
#include "uk/thread.h"
#endif

#ifdef CONFIG_LIBUKSIGNAL
#include <uk/uk_signal.h>
#endif

#include <ushell/ushell.h>
#include "ushell_api.h"

#include <string.h>
#include <stdio.h>

#define BUFSIZE 128

__u64 ushell_interrupt;
__u64 ushell_in_shell_context;
__u64 ushell_original_rax;
__u64 ushell_original_rip;
int ushell_mounted;

//-------------------------------------
// ushel API

// #define _USE_MMAP // use mmap()

void *ushell_alloc_memory(unsigned long size)
{
	void *addr = NULL;
	unsigned pages = (size + PAGE_SIZE) / PAGE_SIZE;

#ifdef _USE_MMAP
	addr = mmap(NULL, size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON,
		    -1, 0);
	if (code == MAP_FAILED || code == 0) {
		uk_pr_info("ushell: mmap failed: code=%ld\n", (long)code);
		ushell_puts("Failed to run command\n");
		return;
	}
#else
	struct uk_pagetable *pt = ukplat_pt_get_active();
	// FIXME: find proper vaddr
	addr = (void *)0x80000000;
	int rc = ukplat_page_map(pt, (long long)addr, __PADDR_ANY, pages,
				 PAGE_ATTR_PROT_WRITE | PAGE_ATTR_PROT_EXEC, 0);
	UK_ASSERT(rc == 0);
#endif
	UK_ASSERT(addr);
	return addr;
}

void ushell_free_memory(void *addr, unsigned long size)
{
	unsigned pages = (size + PAGE_SIZE) / PAGE_SIZE;

#ifdef _USE_MMAP
	munmap(code, size);
#else
	struct uk_pagetable *pt = ukplat_pt_get_active();
	ukplat_page_unmap(pt, (long long)addr, pages, 0);
#endif
}

//-------------------------------------

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

static unsigned ushell_gets(char *buf, unsigned size)
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
	return i;
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

	if (!ushell_mounted) {
		ushell_puts("fs is not mounted\n");
		return;
	}

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
	unsigned size;
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
	fseek(fp, 0, SEEK_SET);

	code = ushell_alloc_memory(size);

	fread(code, size, 1, fp);
	fclose(fp);
	uk_pr_info("ushell: load\n");

#if 0
	uk_hexdumpC(code, size);
#endif

	// run
	int (*func)(int, char *[]) = code;
	r = func(argc, argv);
	snprintf(buf, sizeof(buf), "%d\n", r);
	ushell_puts(buf);

	ushell_free_memory(code, size);
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
#ifdef CONFIG_LIBUKSIGNAL
	} else if (!strcmp(cmd, "kill")) {
		if (argc >= 2) {
			int sig = atoi(argv[1]);
			raise(sig);
		} else {
			ushell_puts("Usage: kill <num>\n");
		}
#endif
#ifdef CONFIG_APPCOUNT
	} else if (!strcmp(cmd, "set_count")) {
		void set_count(int);
		int n = 0;
		if (argc >= 2) {
			n = atoi(argv[1]);
		}
		set_count(n);
#endif
#ifdef CONFIG_LIBSQLITE
	} else if (!strcmp(cmd, "sqlite3_save")) {
		void sqlite3_save();
		ushell_puts("sqlite3_save\n");
		sqlite3_save();
#endif
	} else if (!strcmp(cmd, "quit")) {
		ushell_puts("bye\n");
		return 1;
	} else {
		ushell_puts("Error: unknown command: ");
		ushell_puts(cmd);
		ushell_puts("\n");
	}
	return 0;
}

static int ushell_mount()
{
	const char *rootdev = "fs0";
	const char *rootfs = "9pfs";
	int rootflags = 0;
	char *path = "/ushell";
	const char *rootopts = "";

	if (ushell_mounted) {
		return 0;
	}

#if 1
	int ret = mkdir(path, S_IRWXU);
	if (ret != 0 && errno != EEXIST) {
		/* Root file system is not mounted. Therefore we will mount
		 * ushell fs as a rootfs.
		 */
		path = "/";
	}
#endif

	uk_pr_info("ushell: mount fs to %s\n", path);
	if (mount(rootdev, path, rootfs, rootflags, rootopts) != 0) {
		uk_pr_crit("Failed to mount %s (%s) at %s: errno=%d\n", rootdev,
			   rootfs, path, errno);
		return -1;
	}
	ushell_mounted = 1;

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

void ushell_main_thread()
{
	int argc, rc;
	char buf[BUFSIZE];
	char *argv[USHELL_MAX_ARGS];

	uk_pr_info("ushell main thread started\n");

	/* Set the current thread runnable in case the main thread is sleeping
	 */
#if CONFIG_LIBUKSCHED
	struct uk_thread *current = uk_thread_current();
	__snsec wakeup_time = current->wakeup_time;
	int thread_runnable = is_runnable(current);
	uk_thread_wake(current);
#endif

	rc = ushell_mount();
#if 0
	if (rc < 0) {
		return;
	}
#endif

	/* To enter ushell, user need to send something (usually a new line)
	 * to the virtio-console. Discard that input */
	ushell_gets(&buf[0], BUFSIZE);

	while (1) {
		ushell_print_prompt();
		unsigned i = ushell_gets(&buf[0], BUFSIZE);
		if (i == 0)
			continue;
		argc = ushell_split_args(buf, argv);
		rc = ushell_process_cmd(argc, argv);
		if (rc) {
			break;
		}
	}

#if CONFIG_LIBUKSCHED
	if (!thread_runnable && wakeup_time > 0) {
		/* Original main thread was sleeping.
		 * Resume sleeping.
		 */
		uk_thread_block_until(current, wakeup_time);
	}
#endif
}

