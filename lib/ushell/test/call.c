#define USHELL_MAIN __attribute__((section(".text")))

extern int ushell_loader_test_data;
extern int ushell_loader_test_func(int);

USHELL_MAIN
int main() {
	int r;
	ushell_loader_test_data = 100;
	r = ushell_loader_test_func(10);
	r += ushell_loader_test_func(10);
	ushell_loader_test_data = r;
	return r + 42;
}

