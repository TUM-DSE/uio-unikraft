#include <stddef.h>
#include <uk/assert.h>
#include <uk/console.h>
#include <uk/essentials.h>
#include <uk/print.h>

struct uk_console_device *dev = NULL;

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

char uk_console_getc()
{
	UK_ASSERT(dev);
	UK_ASSERT(dev->ops.getc);

	return dev->ops.getc(dev);
}
