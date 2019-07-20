CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres

exeext := .exe

push-libs += -lws2_32
push-libs += -liphlpapi

catch-objs += discover.o
catch-libs += -lws2_32

progs += wincatch

wincatch-objs  = wincatch.o
wincatch-objs += libcatch.o
wincatch-objs += common.o
wincatch-objs += discover.o
wincatch-objs += platform.o
wincatch-objs += sha1.o
wincatch-objs += wincatch.res
wincatch-libs += -lws2_32
objs += $(wincatch-objs)

wincatch$(exeext): $(wincatch-objs)
	$(CC) $(CFLAGS) $^ $(wincatch-libs) -mwindows -o $@

vpath %.rc $(src_topdir)/$(HOST)

%.res: %.rc
	$(WINDRES) $< -O coff -o $@
