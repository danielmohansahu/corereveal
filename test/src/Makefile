CC=gcc
CFLAGS=-Wall  -g

BIN=../bin/

clean:
	rm -r $(BIN)*

rng_guesser:
	$(CC) rng_guesser.c $(CFLAGS) -o $(BIN)rng_guesser

ini_reader:
	$(CC) ini_reader.c $(CFLAGS) -o $(BIN)ini_reader
	cp test_config.ini $(BIN)

sus:
	$(CC) sus.c $(CFLAGS) -o $(BIN)sus

all: rng_guesser ini_reader sus
	mkdir -p $(BIN)/lib
	mkdir -p $(BIN)/lib64
	cp /lib/x86_64-linux-gnu/libc.so.6 $(BIN)/lib
	cp /lib64/ld-linux-x86-64.so.2 $(BIN)/lib64
	
