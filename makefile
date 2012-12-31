CC = gcc
CFLAGS = -Wall -pthread
EXEC = server
SRC = $(wildcard *.c)

$(EXEC) : $(SRC)
	$(CC) $(CFLAGS) -o $(EXEC) $^
