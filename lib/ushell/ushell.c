#include "uk/plat/paging.h"
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/print.h>
#include <uk/hexdump.h>
#include <uk/libparam.h>
#include <vfscore/mount.h>
#include <uk/init.h>

#if CONFIG_LIBUKSCHED
#include "uk/thread.h"
#include "uk/sched.h"
#endif

#ifdef CONFIG_LIBUKSIGNAL
#include <uk/uk_signal.h>
#endif

#include <ushell/ushell.h>
#include "ushell_api.h"

#include <string.h>
#include <stdio.h>

static const char *fsdev = CONFIG_LIBUSHELL_FSDEV;
UK_LIB_PARAM_STR(fsdev);

int ushell_mounted;

//-------------------------------------
// ushel API

// #define _USE_MMAP // use mmap()

void *ushell_alloc_memory(unsigned long size)
{
	unsigned pages = (size + PAGE_SIZE) / PAGE_SIZE;
	void *addr = NULL;

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
	static void *base_addr = (void *)0x80000000;
	addr = base_addr;
	int rc = ukplat_page_map(pt, (long long)addr, __PADDR_ANY, pages,
				 PAGE_ATTR_PROT_READ | PAGE_ATTR_PROT_WRITE
				     | PAGE_ATTR_PROT_EXEC,
				 0);
	UK_ASSERT(rc == 0);
	base_addr = (char *)addr + (pages * PAGE_SIZE);
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

void ushell_puts(char *str)
{
	size_t len = strlen(str);
	ushell_puts_n(str, len);
}

static void ushell_print_prompt()
{
	ushell_puts("> ");
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

static void ushell_free_all_prog(int argc, char *argv[])
{
	ushell_program_free_all();
}

static void ushell_free_prog(int argc, char *argv[])
{
	if (argc != 1) {
		ushell_puts("Usage: free <name>\n");
		return;
	}
	int r = ushell_program_free_prog_name(argv[0]);
	if (r == 0) {
		ushell_puts("program freed\n");
	} else {
		ushell_puts("no such program loaded\n");
	}
}

static void ushell_run(int argc, char *argv[])
{
	char *cmd;
	char buf[128];
	if (argc == 0 || argv[0][0] == '\0') {
		ushell_puts("Usage: run <cmd> [args]\n");
		return;
	}
	cmd = argv[0];

#if 1
	int r, retval;
	r = ushell_program_run(cmd, argc, argv, &retval);
	if (r != 0) {
		/* program is not loaded. load and retry */
		r = ushell_loader_load_elf(cmd);
		if (r != 0) {
			ushell_puts("load error\n");
			return;
		}
		r = ushell_program_run(cmd, argc, argv, &retval);
	}
	if (r == 0) {
		snprintf(buf, sizeof(buf), "%d\n", retval);
		ushell_puts(buf);
	}

#else // old version
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
#endif
}

#endif /* CONFIG_HAVE_LIBC */

static int ushell_process_cmd(int argc, char *argv[])
{
	char buf[128];
	if (argc < 1) {
		/* no command to process */
		return;
	}
	UK_ASSERT(argc >= 1);
	char *cmd = argv[0];
	if (*cmd == '\0') {
		return 0;
	} else if (!strcmp(cmd, "ls")) {
		ushell_listdir(argc, argv);
#ifdef CONFIG_HAVE_LIBC
	} else if (!strcmp(cmd, "run")) {
		ushell_run(argc - 1, argv + 1);
	} else if (!strcmp(cmd, "free")) {
		ushell_free_prog(argc - 1, argv + 1);
	} else if (!strcmp(cmd, "free-all")) {
		ushell_free_all_prog(argc - 1, argv + 1);
	} else if (!strcmp(cmd, "cat")) {
		ushell_cat(argc, argv);
#endif
	} else if (!strcmp(cmd, "load")) {
		int r = ushell_load_symbol(argv[1]);
		snprintf(buf, sizeof(buf), "Load %d symbols\n", r);
		ushell_puts(buf);
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
	if (mount(fsdev, path, rootfs, rootflags, rootopts) != 0) {
		uk_pr_crit("Failed to mount %s (%s) at %s: errno=%d\n", fsdev,
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
	return i - 1;
}

static void ushell_cons_thread(void *arg)
{
	int argc, rc;
	char *buf;
	char *argv[USHELL_MAX_ARGS];
	struct uk_console_events *uevent = (struct uk_console_events *)arg;

	UK_ASSERT(uevent);
	uk_pr_info("ushell main thread started\n");

	rc = ushell_mount();
#if 0
	/* mount error. possibly the fs is already mounted   */
	/* TODO: properly check if the fs is already mounted */
	if (rc < 0) {
		return;
	}
#endif

	/* To enter ushell, user need to send something (usually a new line)
	 * to the virtio-console. Discard that input */

	while (1) {
		ushell_print_prompt();
		buf = uk_console_get_buf();
		if (buf == NULL)
			continue;
		argc = ushell_split_args(buf, argv);
		rc = ushell_process_cmd(argc, argv);
		if (rc) {
			break;
		}
	}
}

static int ushell_init(void)
{
	struct uk_console_device *uk_cdev;
	struct uk_console_events *ushell_event;

	uk_cdev = uk_console_get_dev();
	/*
	 * This function is supposed to start after a console device
	 * has been registered.
	 */
	UK_ASSERT(uk_cdev);

	uk_pr_info("Attached ushell at %s\n", uk_cdev->name);

	ushell_event = &uk_cdev->uk_cdev_evnt;
	ushell_event->thr_s = uk_sched_get_default();
	ushell_event->uk_cons_data.uk_cdev = uk_cdev;
	uk_semaphore_init(&ushell_event->events, 0);
	if (asprintf(&ushell_event->thr_name, "ushell_consdev") < 0) {
		ushell_event->thr_name = NULL;
	}

	ushell_event->thr =
	    uk_sched_thread_create(ushell_event->thr_s, ushell_event->thr_name,
				   NULL, ushell_cons_thread, ushell_event);

	return 0;
}

uk_late_initcall(ushell_init);
