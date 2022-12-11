#define USHELL_MAIN __attribute__((section(".text")))

int a; // .bss

USHELL_MAIN
int main() {
	a += 1;
	return a;
}

