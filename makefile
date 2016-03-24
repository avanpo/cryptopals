CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto

all: set3 set4

set3: set3.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set3 set3.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c

set4: set4.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set4 set4.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c

clean:
	rm set3 set4
