CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto

all: set3

set3: set3.c ../exploits.c ../modes.c ../random.c ../utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set3 set3.c ../exploits.c ../modes.c ../random.c ../utils.c

clean:
	rm set3
