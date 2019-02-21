CC = i686-w64-mingw32-gcc

exeext := .exe

push-objs += win32/net.o
push-objs += win32/clock.o
push-libs += -lws2_32
push-libs += -liphlpapi

catch-objs += win32/net.o
catch-libs += -lws2_32
