#
# This is meant to be built using Borland C++ 3.1
# (Borland C++ 4.0 can also be used, but it will produce ~20K larger
# executable file.)
#

CC = bcc
#CC = tcc
CFLAGS = -d -ls -Dinline= -ml -1

WATT_ROOT = wattcp
INCDIRS = -I. -Icompat -I.. -I$(WATT_ROOT)\include
LIBDIRS = -L$(WATT_ROOT)\lib
LIBS = wattcpl.lib

all: push.exe

push-objs = \
	common.obj \
	dospush.obj \
	push.obj \
	catch.obj \
	libpush.obj \
	libcatch.obj \
	platform.obj \
	sha1.obj

push.exe: $(push-objs)
	$(CC) $(CFLAGS) -e$@ $(LIBDIRS) $(LIBS) @&&!
$**
!

.c.obj:
	$(CC) $(CFLAGS) $(INCDIRS) -c -o$@ $**

common.obj: ..\common.c
	$(CC) $(CFLAGS) $(INCDIRS) -c -o$@ $**

libcatch.obj: ..\libcatch.c
	$(CC) $(CFLAGS) $(INCDIRS) -c -o$@ $**

libpush.obj: ..\libpush.c
	$(CC) $(CFLAGS) $(INCDIRS) -c -o$@ $**

sha1.obj: ..\sha1.c
	$(CC) $(CFLAGS) $(INCDIRS) -c -o$@ $**

clean:
	del *.obj
	del push.exe
