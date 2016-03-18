CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto

all: set3

set3: set3.c libs/exploits.c libs/modes.c libs/random.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set3 set3.c libs/exploits.c libs/modes.c libs/random.c libs/utils.c

clean:
	rm set3
