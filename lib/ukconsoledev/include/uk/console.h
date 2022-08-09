#ifndef __UK_CONSOLE__
#define __UK_CONSOLE__

#ifdef __cplusplus
extern "C" {
#endif

struct uk_console_device;

typedef char (*uk_console_getc_t)(struct uk_console_device *);
typedef void (*uk_console_putc_t)(struct uk_console_device *, char);

struct uk_console_device_ops {
	uk_console_getc_t getc;
	uk_console_putc_t putc;
};

struct uk_console_device {
	char name[16];
	struct uk_console_device_ops ops;
};

void uk_console_register_device(struct uk_console_device *);
void uk_console_putc(char);
void uk_console_puts(char *, int);
char uk_console_getc();

#ifdef __cplusplus
}
#endif

#endif /* __UK_CONSOLE__ */
