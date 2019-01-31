# make
# 	Build the aesgcm tool
# make test
# 	Build the tool and run a self test (encryption + decryption)
# make test V=1
# 	Same as above, but more verbose
# make clean
# 	Remove all generated files

SHELL=/bin/bash

ifeq ($(V),1)
VFLAGS=-v -v
endif

aesgcm: aesgcm.c
	$(CC) -g -o $@ $< -lcrypto

key:
	printf "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" >$@

iv:
	printf "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b" >$@

plaintext:
	dd if=/dev/zero of=$@ bs=1 count=1500

test: aesgcm key iv plaintext
	./aesgcm enc $(VFLAGS) -key key -iv iv -in plaintext -out ciphertext -tag tag
	./aesgcm dec $(VFLAGS) -key key -iv iv -tag tag -in ciphertext -out decrypted
	cmp plaintext decrypted

clean:
	rm -f aesgcm key iv plaintext ciphertext tag decrypted
