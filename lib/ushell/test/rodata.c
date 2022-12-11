#define USHELL_MAIN __attribute__((section(".text")))

// NOTE: gcc optimizes even in -00
const int a = 100;

int f(int x) {
	return x + 1;
}

USHELL_MAIN
int main() {
	return f(a);
}

