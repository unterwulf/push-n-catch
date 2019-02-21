src_topdir = $(CURDIR)
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

progs = push$(exeext) catch$(exeext)
objs = $(sort $(push-objs) $(catch-objs))
deps = $(objs:.o=.d)

all: $(progs)

clean:
	rm -f $(deps) $(objs) $(progs)

push$(exeext): $(push-objs)
	$(CC) $(CFLAGS) $^ $(push-libs) -o $@

catch$(exeext): $(catch-objs)
	$(CC) $(CFLAGS) $^ $(catch-libs) -o $@

.PHONY: all clean

-include $(deps)
