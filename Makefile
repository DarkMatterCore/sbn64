CFLAGS=-std=c99 -pedantic -Wall -O3
#STRIP=i586-mingw32msvc-strip
#CC=i586-mingw32msvc-gcc
STRIP=strip
CC=gcc
EXE_EXT=.exe

PROJECT_NAME=sbn64
EXE_NAME=$(PROJECT_NAME)$(EXE_EXT)

all: $(EXE_NAME)

clean:
	rm -f $(EXE_NAME)

%.exe: %.c
	$(CC) $(CFLAGS) $^ -o $@
	$(STRIP) $@