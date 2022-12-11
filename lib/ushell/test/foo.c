#define NOINLINE __attribute__ ((noinline))
#define USHELL_MAIN __attribute__((section(".text")))

int NOINLINE g(int a) {
	return a * 4;
}

int NOINLINE f(int a) {
	return g(a) + g(a);
}

USHELL_MAIN
int main() {
	return f(3);
}

