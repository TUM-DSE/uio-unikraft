#ifndef __UK_CONSOLE__
#define __UK_CONSOLE__

#include <uk/semaphore.h>
#include <uk/arch/spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RECV_BUF_SIZE	100
#define QBUF_SIZE	128

struct uk_console_device;

typedef char (*uk_console_getc_t)(struct uk_console_device *);
typedef void (*uk_console_putc_t)(struct uk_console_device *, char);

struct uk_console_data {
	struct uk_console_device *uk_cdev;
	char			 recv_buf[RECV_BUF_SIZE][QBUF_SIZE];
	uint64_t		 recv_buf_idx;
	uint64_t		 recv_buf_head;
	__spinlock		 buf_cnts_slock;
};

struct uk_console_events {
	struct uk_semaphore	events; /**< semaphore to trigger events */
	struct uk_console_data	uk_cons_data;   /**< reference to net device */
	struct uk_thread	*thr;   /**< dispatcher thread */
	char			*thr_name;      /**< reference to thread name */
	struct uk_sched		*thr_s; /**< Scheduler for dispatcher. */
};


struct uk_console_device_ops {
	uk_console_getc_t getc;
	uk_console_putc_t putc;
};

struct uk_console_device {
	char name[16];
	struct uk_console_device_ops ops;
	struct uk_console_events uk_cdev_evnt;
};

struct uk_console_device *uk_console_get_dev();
void uk_console_register_device(struct uk_console_device *);
void uk_console_putc(char);
void uk_console_puts(char *, int);
char *uk_console_get_buf();
int uk_cons_put_buffer(struct uk_console_device *cdev,
			char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif /* __UK_CONSOLE__ */
