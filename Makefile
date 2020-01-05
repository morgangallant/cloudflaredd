CC ?= gcc
CFLAGS = -O3
LDFLAGS = -lcurl
BINARY = cloudflaredd

SRCS = cloudflaredd.c

all:
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) -o $(BINARY)

clean:
	$(RM) $(BINARY)