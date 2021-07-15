CFLAGS=-std=c99 -Wall -Wextra -O2
PREFIX=i686-w64-mingw32-
STRIP=$(PREFIX)strip
CC=$(PREFIX)gcc
EXE_EXT=.exe

PROJECT_NAME=sbn64
EXE_NAME=$(PROJECT_NAME)$(EXE_EXT)

all: $(EXE_NAME)

clean:
	rm -f $(EXE_NAME)

%.exe: %.c
	$(CC) $(CFLAGS) $^ -o $@
	$(STRIP) $@
