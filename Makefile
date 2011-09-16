CC=gcc
CFLAGS=-Wall -O3 -Werror
LDFLAGS=-lm -pthread -lft -lz

flowy: flowy.o ftreader.o auto_comps.o utils.o grouper_fptr.o auto_assign.o
	$(CC) $^ $(LDFLAGS) -o $@

#treesearchmain: treesearchmain.o treesearch.o ftreader.o utils.o
#	$(CC) $^ $(LDFLAGS) -o $@

auto_assign.c auto_comps.c auto_comps.h: fun_gen.py
	python $^

clean:
	rm -f flowy *.o auto_assign.c auto_comps.c auto_comps.h
