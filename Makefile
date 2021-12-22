PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
INSTALLDIR = $(DESTDIR)$(BINDIR)
CFLAGS += -Wall -g
OBJS = sha1.o
LDLIBS = -lsqlite3

.PHONY: all clean install

all: ideviceunback

ideviceunback: $(OBJS) ideviceunback.c

clean:
	$(RM) ideviceunback *.o

install: ideviceunback
	mkdir -p $(INSTALLDIR)
	install ideviceunback $(INSTALLDIR)
