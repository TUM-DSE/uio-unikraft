#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

void *addr;

void f()
{
	printf("hello\n");
}

void jump()
{
	asm volatile("jmp *addr");
}

int main()
{
	/* jmp *0x0(%rip) */
	char code[16] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc};
	addr = mmap(NULL, 4096, PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr != MAP_FAILED);
	memcpy(addr, code, 16);
	long faddr = (long)&f;
	memcpy((char *)addr + 6, &faddr, 8);

	jump();

	munmap(addr, 4096);

	return 0;
}
