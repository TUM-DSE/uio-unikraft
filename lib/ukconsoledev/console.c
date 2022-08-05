#include <stddef.h>
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

void uk_console_putc(char ch) {}

char uk_console_getc()
{
	char a = 'a';
	return a;
}
