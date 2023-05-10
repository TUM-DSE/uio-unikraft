#include <stddef.h>
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/essentials.h>
#include <uk/print.h>
#include <uk/plat/spinlock.h>
#include <string.h>

struct uk_console_device *dev = NULL;

static int console_get_buffer(struct uk_console_data *cdata, char **buffer)
{
	unsigned long flags;
	uint64_t tmp_buf_idx, tmp_buf_head;

	UK_ASSERT(cdata);

	/*
	 * Grab the values fast and release the lock
	 * We might not need to change tmp_buf_idx
	 */
	ukplat_spin_lock_irqsave(&(cdata->buf_cnts_slock), flags);
	tmp_buf_idx = cdata->recv_buf_idx;
	tmp_buf_head = cdata->recv_buf_head;
	ukplat_spin_unlock_irqrestore(&(cdata->buf_cnts_slock), flags);

	if (tmp_buf_idx == tmp_buf_head) {
		// no data
		return -1;
	}
	*buffer = cdata->recv_buf[tmp_buf_idx];
	ukplat_spin_lock_irqsave(&(cdata->buf_cnts_slock), flags);
	cdata->recv_buf_idx = (cdata->recv_buf_idx + 1) % VTCONS_RECV_BUF_SIZE;
	ukplat_spin_unlock_irqrestore(&(cdata->buf_cnts_slock), flags);
	return 0;
}

struct uk_console_device *uk_console_get_dev()
{
	return dev;
}

void uk_console_register_device(struct uk_console_device *uk_cdev)
{
	if (dev != NULL) {
		uk_pr_err("Multiple console devices are not supported yet\n");
		return;
	}
	dev = uk_cdev;
	uk_pr_info("uk_console: registered: %s\n", dev->name);
}

void uk_console_putc(char ch)
{
	UK_ASSERT(dev);
	UK_ASSERT(dev->ops.putc);

	dev->ops.putc(dev, ch);
}

void uk_console_puts(char *str, int len)
{
	int i;

	UK_ASSERT(len >= 0);

	for (i = 0; i < len; i++) {
		if (str[i] == '\0') {
			break;
		}
		uk_console_putc(str[i]);
	}
}

char *uk_console_get_buf()
{
	char *buf = NULL;
	int rc = 0;
	struct uk_console_events *ev_cons;

	UK_ASSERT(dev);
	ev_cons = &(dev->uk_cdev_evnt);
	UK_ASSERT(ev_cons);

	for (;;) {
		// Get stored buffer
		rc = console_get_buffer(&ev_cons->uk_cons_data, &buf);
		if (rc == -1) {
			uk_semaphore_down(&ev_cons->events);
			continue;
		}
		return buf;
	}
	return buf;
}

int uk_console_put_buffer(struct uk_console_device *cdev, char *buf, int len)
{
	int flags;
	struct uk_console_events *cdev_evnt = &(dev->uk_cdev_evnt);
	struct uk_console_data *cons_data = &(cdev_evnt->uk_cons_data);

	UK_ASSERT(cdev);
	UK_ASSERT(cdev_evnt);
	UK_ASSERT(cons_data);
	UK_ASSERT(buf);

	if (len >= VTCONS_QBUF_SIZE) {
		uk_pr_err("Too big incoming virtio console buffer\n");
		return -1;
	}
	buf[len] = '\0';
	ukplat_spin_lock_irqsave(&(cons_data->buf_cnts_slock), flags);
	if ((cons_data->recv_buf_head + 1) % VTCONS_RECV_BUF_SIZE
	    == cons_data->recv_buf_idx) {
		uk_pr_err("Unikraft console: recv buffer full\n");
		ukplat_spin_unlock_irqrestore(&(cons_data->buf_cnts_slock),
					      flags);
		return -1;
	} else {
		memcpy(cons_data->recv_buf[cons_data->recv_buf_head], buf, len);
		cons_data->recv_buf_head =
		    (cons_data->recv_buf_head + 1) % VTCONS_RECV_BUF_SIZE;
	}
	ukplat_spin_unlock_irqrestore(&(cons_data->buf_cnts_slock), flags);
	uk_semaphore_up(&cdev_evnt->events);
	return 0;
}
