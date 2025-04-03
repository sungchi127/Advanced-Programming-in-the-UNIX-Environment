#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	long temp = 0x8787878787878787;
	// fptr("canary->%lx\n", *(long*)((char*)&temp + 8));
	// fptr("rbp->%lx\n", (*(long*)((char*)&temp + 16)));
	// fptr("return address->%lx\n", (*(long*)((char*)&temp + 24)));
	fptr("%lx\n", *(long*)((char*)&temp + 8));
	fptr("%lx\n", (*(long*)((char*)&temp + 16)));
	fptr("%lx\n", (*(long*)((char*)&temp + 24)));
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}
