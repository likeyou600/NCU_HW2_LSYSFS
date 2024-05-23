/**
 * Less Simple, Yet Stupid Filesystem.
 *
 * Mohammed Q. Hussain - http://www.maastaar.net
 *
 * This is an example of using FUSE to build a simple filesystem. It is a part of a tutorial in MQH Blog with the title "Writing Less Simple, Yet Stupid Filesystem Using FUSE in C": http://maastaar.net/fuse/linux/filesystem/c/2019/09/28/writing-less-simple-yet-stupid-filesystem-using-FUSE-in-C/
 *
 * License: GNU GPL
 */

#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

 //openssl
#include <openssl/aes.h>
#include <openssl/rand.h>


 // ... //
char key[256][256];

char dir_list[256][256];
int curr_dir_idx = -1;

char files_list[256][256];
int curr_file_idx = -1;

char files_content[256][256];
int curr_file_content_idx = -1;

void add_dir(const char* dir_name)
{
	curr_dir_idx++;
	strcpy(dir_list[curr_dir_idx], dir_name);
}

int is_dir(const char* path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
		if (strcmp(path, dir_list[curr_idx]) == 0)
			return 1;

	return 0;
}

void add_file(const char* filename)
{
	curr_file_idx++;
	strcpy(files_list[curr_file_idx], filename);

	curr_file_content_idx++;
	strcpy(files_content[curr_file_content_idx], "");
}

int is_file(const char* path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
		if (strcmp(path, files_list[curr_idx]) == 0)
			return 1;

	return 0;
}

int get_file_index(const char* path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
		if (strcmp(path, files_list[curr_idx]) == 0)
			return curr_idx;

	return -1;
}

void write_to_file(const char* path, const char* new_content)
{
	int file_idx = get_file_index(path);
	printf("file_idx : %d\n", file_idx);

	if (file_idx == -1) // No such file
		return;

	//gen key
	unsigned char aes_key[32];

	// 256bits 32byte
	RAND_bytes(aes_key, 32);
	printf("generated AES-256 key：\n");
	for (int i = 0; i < 32; ++i) {
		printf("%02X", aes_key[i]);
	}
	printf("\n");
	memcpy(key[file_idx], aes_key, 32);

	printf("encrypting...\n");
	printf("\n");

	unsigned char ciphertext[256];
	int outlen, tmplen;
	EVP_CIPHER_CTX* ctx;

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
	EVP_EncryptUpdate(ctx, ciphertext, &outlen, (const unsigned char*)new_content, strlen(new_content));
	EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
	outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

	// strcpy(files_content[file_idx], new_content);
	strcpy(files_content[file_idx], ciphertext);
	printf("\n");

}

void remove_file(const char* path)
{
	int file_idx = get_file_index(path);
	printf("delete_file_idx : %d \n", file_idx);

	if (file_idx == -1) // No such file
		return;

	// Shift all files down by one
	for (int i = file_idx; i < curr_file_idx; i++) {
		strcpy(files_list[i], files_list[i + 1]);
		strcpy(files_content[i], files_content[i + 1]);
	}

	// Clear the last entry
	files_list[curr_file_idx][0] = '\0';
	files_content[curr_file_idx][0] = '\0';

	curr_file_idx--;
	curr_file_content_idx--;
	printf("\n");
}
// ... //

static int do_getattr(const char* path, struct stat* st)
{
	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time(NULL); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time(NULL); // The last "m"odification of the file/directory is right now

	if (strcmp(path, "/") == 0 || is_dir(path) == 1)
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if (is_file(path) == 1)
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}

	return 0;
}

static int do_readdir(const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
	filler(buffer, ".", NULL, 0); // Current Directory
	filler(buffer, "..", NULL, 0); // Parent Directory

	if (strcmp(path, "/") == 0) // If the user is trying to show the files/directories of the root directory show the following
	{
		for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
			filler(buffer, dir_list[curr_idx], NULL, 0);

		for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
			filler(buffer, files_list[curr_idx], NULL, 0);
	}

	return 0;
}

static int do_read(const char* path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi)
{
	printf("do_read\n");

	int file_idx = get_file_index(path);
	printf("file_idx : %d\n", file_idx);

	if (file_idx == -1)
		return -1;

	char* content = files_content[file_idx];

	// Perform decryption
	unsigned char decrypted_text[256];
	int outlen, tmplen;
	EVP_CIPHER_CTX* ctx;

	// Use the same key as used for encryption
	unsigned char aes_key[32];
	memcpy(aes_key, key[file_idx], 32);

	printf("stored AES-256 key：\n");
	for (int i = 0; i < 32; ++i) {
		printf("%02X", aes_key[i]);
	}
	printf("\n");



	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
	EVP_DecryptUpdate(ctx, decrypted_text, &outlen, (const unsigned char*)content + offset, strlen((char*)content));
	EVP_DecryptFinal_ex(ctx, decrypted_text + outlen, &tmplen);
	outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);
	printf("decrypting...\n");

	decrypted_text[outlen + tmplen] = '0';
	// Copy decrypted text to buffer
	memcpy(buffer, decrypted_text, outlen);

	return outlen;

	// memcpy(buffer, content + offset, size);

	// return strlen(content) - offset;
}

static int do_mkdir(const char* path, mode_t mode)
{
	printf("do_mkdir\n");
	path++;
	add_dir(path);

	return 0;
}

static int do_mknod(const char* path, mode_t mode, dev_t rdev)
{
	printf("do_mknod\n");
	path++;
	add_file(path);

	return 0;
}

static int do_write(const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* info)
{
	printf("do_write\n");
	write_to_file(path, buffer);

	return size;
}
static int do_rm(const char* path)
{
	printf("do_rm\n");

	remove_file(path);

	return 0;
}
static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,
	.mkdir = do_mkdir,
	.mknod = do_mknod,
	.write = do_write,
	.unlink = do_rm,

};

int main(int argc, char* argv[])
{
	printf("\n");
	printf("\n");
	return fuse_main(argc, argv, &operations, NULL);
}
