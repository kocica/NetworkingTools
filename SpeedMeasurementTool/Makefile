CC=g++

CCFLAGS=-std=c++14 -pedantic -Wall -pthread

all: main

main: main.o
	$(CC) $(CCFLAGS) main.o -o $@

main.o: main.cpp
	$(CC) $(CCFLAGS) -c main.cpp -o $@

clean:
	rm -f *.o
	rm -f main
