exec_prefix = /
libdir = $(exec_prefix)/lib

INSTALL = install
CC = gcc
CFLAGS = -O2 -Wall
LD = ld

ALL_CFLAGS = $(CFLAGS) -fPIC
ALL_LDFLAGS = $(LDFLAGS) -shared -Wl,-x

all: libnss_nonlocal.so.2 linktest

libnss_nonlocal.so.2: nonlocal-passwd.o nonlocal-group.o nonlocal-shadow.o
	$(CC) -o $@ $(ALL_LDFLAGS) -Wl,-soname,$@ $^ $(LOADLIBES) $(LDLIBS)

%.o: %.c
	$(CC) -c $(ALL_CFLAGS) $(CPPFLAGS) $<

nonlocal-passwd.o: nonlocal-passwd.c nsswitch-internal.h nonlocal.h
nonlocal-group.o: nonlocal-group.c nsswitch-internal.h nonlocal.h
nonlocal-shadow.o: nonlocal-shadow.c nsswitch-internal.h nonlocal.h

linktest: libnss_nonlocal.so.2
	$(LD) --entry=0 -o /dev/null $^

install: libnss_nonlocal.so.2
	$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) -m a+r,u+w $< $(DESTDIR)$(libdir)/

clean:
	rm -f *.so.* *.o test-nonlocal

.PHONY: all linktest install clean
