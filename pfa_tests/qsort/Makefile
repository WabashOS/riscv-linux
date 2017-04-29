CFLAGS := -O3 -static

qsort: qsort_main.c dataset1.h util.h
	riscv64-unknown-linux-gnu-gcc ${CFLAGS} -o qsort qsort_main.c

qsort_nat: qsort_main.c util.h
	gcc ${CFLAGS} -o qsort qsort_main.c
