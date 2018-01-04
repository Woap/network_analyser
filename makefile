CC=gcc
CFLAGS=-c -Wall

all : bin/analyse

bin/analyse : obj/analyse.o
	$(CC) -o analyse obj/analyse.o  -lpcap
	mv analyse bin/

obj/analyse.o : src/analyse.c
	$(CC) $(CFLAGS) src/analyse.c -O2 -lpcap
	mv analyse.o obj/

archive :
	tar -czvf archive_analyseur_ibis.tar.gz ./

clean :
	rm -rf obj/* bin/analyse
