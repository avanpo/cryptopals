CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto -lgmp

all: set3 set4 set5

set3: set3.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set3 set3.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c

set4: set4.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set4 set4.c libs/ciphers.c libs/exploits.c libs/macs.c libs/random.c libs/utils.c

set5: set5.c libs/pk.c libs/utils.c
	$(CC) $(CFLAGS) $(LIBS) -o set5 set5.c libs/pk.c libs/utils.c

clean:
	rm set3 set4 set5
