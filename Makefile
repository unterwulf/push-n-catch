src_topdir = $(CURDIR)
progs =
objs =

HOST ?= posix
DEPFLAGS = -MMD -MP
CFLAGS += $(DEPFLAGS) -Wall -W -I$(src_topdir)

push-objs  = push.o
push-objs += common.o
push-objs += net_common.o
push-objs += sha1.o

catch-objs  = catch.o
catch-objs += common.o
catch-objs += net_common.o
catch-objs += sha1.o

include $(HOST)/include.mk

progs += push$(exeext) catch$(exeext)
objs += $(sort $(push-objs) $(catch-objs))
deps = $(patsubst %.o, %.d, $(filter %.o, $(objs)))

all: $(progs)

test: $(progs)
	tests/run_all

clean:
	rm -f $(deps) $(objs) $(progs)

push$(exeext): $(push-objs)
	$(CC) $(CFLAGS) $^ $(push-libs) -o $@

catch$(exeext): $(catch-objs)
	$(CC) $(CFLAGS) $^ $(catch-libs) -o $@

wincatch$(exeext): $(wincatch-objs)
	$(CC) $(CFLAGS) $^ $(wincatch-libs) -mwindows -o $@

%.res: %.rc
	$(WINDRES) $< -O coff -o $@

.PHONY: all clean

-include $(deps)
