#include <stddef.h>
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/essentials.h>
#include <uk/print.h>

struct uk_console_device *dev = NULL;

static int virtio_console_getc_from_buffer(struct uk_console_data *cdata,
					   char *c)
{
	UK_ASSERT(cdata);

	if (cdata->recv_buf_idx == cdata->recv_buf_head) {
		// no data
		return -1;
	}
	*c = cdata->recv_buf[cdata->recv_buf_idx];
	cdata->recv_buf_idx = (cdata->recv_buf_idx + 1) % RECV_BUF_SIZE;
	return 0;
}

static char virtio_console_getc(struct uk_console_device *uk_cdev)
{
	char c;
	int rc = 0;
	struct uk_console_events *ev_cons = &(uk_cdev->uk_cdev_evnt);

	UK_ASSERT(ev_cons);

	for (;;) {
		// return char if any in the buffer
		rc = virtio_console_getc_from_buffer(&ev_cons->uk_cons_data, &c);
		if (rc == -1) {
			uk_pr_info("waiting..\n");
			uk_semaphore_down(&ev_cons->events);
			continue;
		}
		uk_pr_info("back on.. got %c\n", c);
		return c;
	}
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

char uk_console_getc()
{
	UK_ASSERT(dev);
	//UK_ASSERT(dev->ops.getc);

	//return dev->ops.getc(dev);
	return virtio_console_getc(dev);
}

int uk_cons_put_buffer(struct uk_console_device *cdev,
			char (*buf)[QBUF_SIZE], int len)
{
	int i;
	struct uk_console_events *cdev_evnt = &(dev->uk_cdev_evnt);
	struct uk_console_data *cons_data = &(cdev_evnt->uk_cons_data);

	UK_ASSERT(cdev);
	UK_ASSERT(cdev_evnt);
	UK_ASSERT(cons_data);

	for (i = 0; i < len; i++) {
		if ((cons_data->recv_buf_head + 1) % RECV_BUF_SIZE
		    == cons_data->recv_buf_idx) {
			uk_pr_err("Unikraft console: recv buffer full\n");
			return -1;
		} else {
			cons_data->recv_buf[cons_data->recv_buf_head] = (*buf)[i];
			cons_data->recv_buf_head =
			    (cons_data->recv_buf_head + 1) % RECV_BUF_SIZE;
		}
	}
	uk_semaphore_up(&cdev_evnt->events);
	return 0;
}

