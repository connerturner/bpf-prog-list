CC=gcc
CFLAGS=I.
BDIR=./bin

.PHONY: run clean

all: buildir prog run

buildir:
	mkdir -p $(BDIR)
prog:
	$(CC) -o $(BDIR)/proglist proglist.c
run: prog
	$(BDIR)/proglist

clean:
	rm -rf $(BDIR)

