#define USHELL_MAIN __attribute__((section(".text")))

int a = 100; // .data
int b; // .bss

USHELL_MAIN
int main() {
	b += 1;
	return a + b;
}

