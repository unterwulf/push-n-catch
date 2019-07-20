DEPFLAGS = -MMD -MP
CFLAGS += $(DEPFLAGS) -Wall -W -I$(src_topdir)/$(HOST) -I$(src_topdir)
progs =
exeext =

push-objs  = push.o
push-objs += common.o
push-objs += libpush.o
push-objs += platform.o
push-objs += sha1.o

catch-objs  = catch.o
catch-objs += common.o
catch-objs += libcatch.o
catch-objs += platform.o
catch-objs += sha1.o

-include $(src_topdir)/$(HOST)/include.mk

progs += push catch
fqprogs = $(addsuffix $(exeext),$(progs))
objs += $(sort $(push-objs) $(catch-objs))
deps = $(patsubst %.o, %.d, $(filter %.o, $(objs)))

vpath %.c $(src_topdir)/$(HOST) $(src_topdir)

all: $(fqprogs)

clean:
	rm -f $(deps) $(objs) $(fqprogs)

push$(exeext): $(push-objs)
	$(CC) $(CFLAGS) $^ $(push-libs) -o $@

catch$(exeext): $(catch-objs)
	$(CC) $(CFLAGS) $^ $(catch-libs) -o $@

.PHONY: all clean

-include $(deps)
