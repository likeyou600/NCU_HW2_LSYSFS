COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c

# OpenSSL paths (adjust these if OpenSSL is installed in a different location)
OPENSSL_INCLUDE = -I./openssl/include
OPENSSL_LIB = -L./openssl -lssl -lcrypto

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o lsysfs `pkg-config fuse --cflags --libs` $(OPENSSL_INCLUDE) $(OPENSSL_LIB)
	echo 'To Mount: ./lsysfs -f [mount point]'

clean:
	rm ssfs
