CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres

exeext := .exe

push-objs += win32/net.o
push-objs += win32/clock.o
push-libs += -lws2_32
push-libs += -liphlpapi

catch-objs += win32/net.o
catch-libs += -lws2_32

progs += wincatch$(exeext)

wincatch-objs  = win32/wincatch.o
wincatch-objs += win32/net.o
wincatch-objs += libcatch.o
wincatch-objs += common.o
wincatch-objs += net_common.o
wincatch-objs += sha1.o
wincatch-objs += win32/wincatch.res
wincatch-libs += -lws2_32
objs += $(wincatch-objs)
