AFL_DIR=../../AFLplusplus
CFLAGS=-O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

all: hook

hook: hook.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -c hook.c -I$(AFL_DIR)
	$(CC) -shared -o libhook.so hook.o

clean:
	$(RM) *.so *.o
