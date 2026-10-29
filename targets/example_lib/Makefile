CC = clang
CFLAGS = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all
LIB = libexample.a

all: $(LIB)

vuln.o: vuln.c
	$(CC) $(CFLAGS) -c vuln.c -o vuln.o

$(LIB): vuln.o
	ar rcs $(LIB) vuln.o

clean:
	rm -f *.o *.a

.PHONY: all clean
