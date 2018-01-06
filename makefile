CC=gcc
CFLAGS=-c -Wall

all : bin/analyse

bin/analyse : obj/analyse.o obj/print_functions.o
	$(CC) -o analyse obj/analyse.o obj/print_functions.o  -lpcap
	mv analyse bin/

obj/print_functions.o : src/print_functions.c include/print_functions.h
	$(CC) $(CFLAGS) src/print_functions.c include/print_functions.h -O2 -lpcap
	mv print_functions.o obj/

obj/analyse.o : src/analyse.c
	$(CC) $(CFLAGS) src/analyse.c -O2 -lpcap
	mv analyse.o obj/

archive :
	tar -czvf archive_analyseur_ibis.tar.gz *

clean :
	rm -rf obj/* bin/analyse
