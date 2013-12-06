all: libpib-rdmav2.so

libpib-rdmav2.so: src/pib.c
	gcc -g -Wall -fPIC -shared -Wl,--version-script=src/pib.map $< -o $@

clean:
	rm -rf libpib-rdmav2.so

.PHONY: all clean
