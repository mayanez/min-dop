# TODO: Only works w/ clang atm.
# Need to make sure globals are in defined order.
CC = clang
CFLAGS = -std=c99 -fno-zero-initialized-in-bss -fno-stack-protector -g3 -gdwarf-2 -O0 -m32

ifdef CODE_COVERAGE
CFLAGS += -fprofile-arcs -ftest-coverage -DCODE_COVERAGE
endif

.PHONY: all clean

all: vuln_srv

vuln_srv: vuln_srv.c

clean:
	rm -rf *.o *.gcda *.gcno *.gcov vuln_srv
