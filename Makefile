CC=gcc
CFLAGS=I.
BDIR=./bin

.PHONY: run clean debug

all: buildir prog 
debug: buildir prog-g

buildir:
	mkdir -p $(BDIR)
prog:
	$(CC) -o $(BDIR)/proglist util.c proglist.c
prog-g:
	$(CC) -g -o $(BDIR)/proglist util.c proglist.c
run: prog
	$(BDIR)/proglist

clean:
	rm -rf $(BDIR)

