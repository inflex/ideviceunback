CFLAGS= -Wall -g
OBJS= sha1.o
LDLIBS= -lsqlite3

all: ideviceunback

ideviceunback: $(OBJS) ideviceunback.c

clean:
	$(RM) ideviceunback *.o

install: ideviceunback
	install ideviceunback /usr/local/bin
