#include <uk/assert.h>
#include <uk/console.h>
#include <uk/essentials.h>
#include <uk/print.h>

#include <ushell/ushell.h>

#include <string.h>

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
	while (*p != '\0' && *p == ' ') {
		p++;
	}
	return p;
}

int ushell_process_cmd(char *cmd)
{
	cmd = strip_str(cmd);
	if (*cmd == '\0') {
		return 0;
	} else if (!strcmp(cmd, "quit")) {
		ushell_puts("bye\n");
		return 1;
	} else {
		ushell_puts("Error: unknown command\n");
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
