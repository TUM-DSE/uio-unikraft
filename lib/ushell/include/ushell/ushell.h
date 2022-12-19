#ifndef __USHELL__
#define __USHELL__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_LIBUSHELL_MPK
#include <sys/mman.h>
#include <uk/pku.h>
#include <uk/plat/config.h>

#define DEFAULT_PKEY 0

static int disable_write()
{
	int rc = pkey_set_perm(PROT_READ, DEFAULT_PKEY);
	if (rc < 0)
		uk_pr_err("Could not set permisisons for dfault pkey%d\n", errno);

	return rc;
}

static int enable_write()
{
	int rc = pkey_set_perm(PROT_READ | PROT_WRITE, DEFAULT_PKEY);
	if (rc < 0)
		uk_pr_err("Could not set permisisons for dfault pkey%d\n", errno);

	return rc;
}

#define unikraft_call_wrapper(fname, ...)			\
do {								\
	pkey_set_perm(PROT_READ | PROT_WRITE, DEFAULT_PKEY);	\
	fname(__VA_ARGS__);					\
	pkey_set_perm(PROT_READ, DEFAULT_PKEY);			\
} while (0)

#define unikraft_call_wrapper_ret(retval, fname, ...)		\
do {								\
	pkey_set_perm(PROT_READ | PROT_WRITE, DEFAULT_PKEY);	\
	retval = fname(__VA_ARGS__);				\
	pkey_set_perm(PROT_READ, DEFAULT_PKEY);			\
} while (0)

#else

#define unikraft_call_wrapper(fname, ...)			\
do {								\
	fname(__VA_ARGS__);					\
} while (0)

#define unikraft_call_wrapper_ret(retval, fname, ...)		\
do {								\
	retval = fname(__VA_ARGS__);				\
} while (0)
#endif /*CONFIG_LIBUSHELL_MPK */

void ushell_spawn_shell();

#ifdef __cplusplus
}
#endif

#endif /* __USHELL__ */
