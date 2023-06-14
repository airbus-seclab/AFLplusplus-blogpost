CFLAGS=-O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

all: target libhook libcustom_mutator

target: target.c
	$(CC) $(CFLAGS) -o target target.c -lssl -lcrypto

libhook:
	$(MAKE) -C hook all

libcustom_mutator:
	$(MAKE) -C mutator all

clean:
	$(RM) target
	$(MAKE) -C hook clean
	$(MAKE) -C mutator clean
