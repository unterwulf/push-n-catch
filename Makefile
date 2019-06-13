src_topdir = $(CURDIR)

HOST ?= posix
HOSTMAKE = $(MAKE) -f $(src_topdir)/common.mk -C $(builddir)

builddir = build/$(HOST)

export src_topdir HOST builddir

all:| $(builddir)
	$(HOSTMAKE) $@

test:
	tests/run_all $(HOST)

clean:
	if test -d $(builddir); then $(HOSTMAKE) clean; fi

distclean:
	$(RM) -r build

$(builddir):
	mkdir -p $@

.PHONY: all clean distclean
