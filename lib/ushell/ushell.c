#include <uk/assert.h>
#include <uk/console.h>
#include <uk/essentials.h>
#include <uk/print.h>

#include <ushell/ushell.h>

#include <string.h>

#define BUFSIZE 128

static void ushell_print_prompt()
{
	uk_console_puts("> ", 2);
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

int ushell_process_cmd(char *cmd)
{
	if (!strcmp(cmd, "quit")) {
		uk_console_puts("bye\n", 4);
		return 1;
	} else {
		uk_pr_info("ushell: unknown command: %s\n", cmd);
	}
	return 0;
}

void ushell_spawn_shell()
{
	int rc;
	char buf[BUFSIZE];

	uk_pr_info("ushell spawn\n");

	while (1) {
		ushell_print_prompt();
		ushell_gets(&buf[0], BUFSIZE);
		rc = ushell_process_cmd(buf);
		if (rc) {
			break;
		}
	}
}
