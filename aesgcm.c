// SPDX-License-Identifier: BSD-2-Clause

#include <assert.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>   

static int verbose;

#define V(x) do { if (verbose) { x } } while (0)
#define VV(x) do { if (verbose >= 2) { x } } while (0)

static void usage(const char *progname)
{
	printf("Usage: %s enc [-v] -key <keyfile> -iv <ivfile> "
			"-in <infile> [-out <outfile>] [-tag <tagfile>]\n",
			progname);
	printf("       %s dec [-v] -key <keyfile> -iv <ivfile> -tag <tagfile> "
			"-in <infile> [-out <outfile>]\n",
			progname);
	exit(0);
}

void handleErrors(void)
{
	unsigned long errCode;

	printf("An error occurred\n");
	while(errCode = ERR_get_error())
	{
		char *err = ERR_error_string(errCode, NULL);
		printf("%s\n", err);
	}
	abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
			int aad_len, unsigned char *key, unsigned char *iv,
			int iv_len, unsigned char *ciphertext,
			unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, ciphertext_len = 0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad && aad_len > 0)
	{
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
			handleErrors();
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(plaintext)
	{
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			handleErrors();

		ciphertext_len = len;
	}

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
			int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
			int iv_len, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, plaintext_len = 0, ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad && aad_len > 0)
	{
		if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
			handleErrors();
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(ciphertext)
	{
		if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			handleErrors();

		plaintext_len = len;
	}

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

static void *read_file(const char *fname, size_t *fsize)
{
	FILE *file;
	void *buf = NULL;
	unsigned char *p = NULL;
	size_t bufsize = 0;
	size_t rd = 0;
	size_t n;

	file = fopen(fname, "rb");
	if (!file) {
		err(1, "%s", fname);
		exit(1);
	}
	while (!feof(file)) {
		if (bufsize - rd < 1024) {
			bufsize += 1024;
			buf = realloc(buf, bufsize);
			if (!buf)
				errx(1, "out of memory");
			if (!p)
				p = buf;
		}
again:
		n = fread(p, 1, 1024, file);
		if (!n) {
			if (errno == EINTR)
				goto again;
			break;
		}
		p += n;
		rd += n;
	}
	fclose(file);
	if (fsize)
		*fsize = rd;
	V(printf("Read file '%s': %zu bytes read\n", fname, rd););
	return buf;
}

static void write_file(const char *fname, void *buf, size_t size)
{
	FILE *file;
	size_t written;

	file = fopen(fname, "wb");
	if (!file) {
		err(1, "%s", fname);
		exit(1);
	}
	written = fwrite(buf, size, 1, file);
	V(printf("Write file '%s': %zu bytes written\n", fname,
				written * size););
}

static void encode_wrapper(int argc, char *argv[])
{
	int i;
	void *in = NULL;
	size_t in_size = 0;
	void *key = NULL;
	size_t key_size = 0;
	void *out = NULL;
	size_t out_size;
	void *iv = NULL;
	size_t iv_size;
	unsigned char tag[16] = {};

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-in")) {
			i++;
			if (i == argc)
				errx(1, "-in: missing file name");
			in = read_file(argv[i], &in_size);
			assert(in);
		}
		if (!strcmp(argv[i], "-key")) {
			i++;
			if (i == argc)
				errx(1, "-key: missing file name");
			key = read_file(argv[i], &key_size);
			assert(key);
			if (key_size != 16)
				errx(1, "-key: key size has to be 16 bytes");
		}
		if (!strcmp(argv[i], "-iv")) {
			i++;
			if (i == argc)
				errx(1, "-iv: missing file name");
			iv = read_file(argv[i], &iv_size);
			assert(iv);
		}
	}
	if (!in_size)
		errx(1, "missing or empty input file (-in)");
	if (!key_size)
		errx(1, "missing key (-key)");
	if (!iv_size)
		errx(1, "missing or empty IV file (-iv)");
	out = malloc(in_size);
	if (!out)
		errx(1, "out of memory");

	VV(printf("Key is:\n"););
	VV(BIO_dump_fp(stdout, key, key_size););
	VV(printf("IV is:\n"););
	VV(BIO_dump_fp(stdout, iv, iv_size););
	VV(printf("Plaintext:\n"););
	VV(BIO_dump_fp(stdout, in, in_size););

	out_size = encrypt(in, in_size, "", 0, key, iv, iv_size, out, tag);
	if (out_size != in_size)
	       errx(1, "Encrypt failed");	

	VV(printf("Ciphertext:\n"););
	VV(BIO_dump_fp(stdout, out, out_size););
	VV(printf("Tag is:\n"););
	VV(BIO_dump_fp(stdout, tag, sizeof(tag)););

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-out")) {
			i++;
			if (i == argc)
				errx(1, "-out: missing file name");
			write_file(argv[i], out, out_size);
		}
		if (!strcmp(argv[i], "-tag")) {
			i++;
			if (i == argc)
				errx(1, "-tag: missing file name");
			write_file(argv[i], tag, sizeof(tag));
		}
	}

	free(in);
	free(out);
	free(key);
	free(iv);
}

static void decode_wrapper(int argc, char *argv[])
{
	int i;
	void *in = NULL;
	size_t in_size = 0;
	void *key = NULL;
	size_t key_size = 0;
	void *out = NULL;
	size_t out_size;
	void *iv = NULL;
	size_t iv_size;
	void *tag = NULL;
	size_t tag_size = 0;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-in")) {
			i++;
			if (i == argc)
				errx(1, "-in: missing file name");
			in = read_file(argv[i], &in_size);
			assert(in);
		}
		if (!strcmp(argv[i], "-key")) {
			i++;
			if (i == argc)
				errx(1, "-key: missing file name");
			key = read_file(argv[i], &key_size);
			assert(key);
			if (key_size != 16)
				errx(1, "-key: key size has to be 16 bytes");
		}
		if (!strcmp(argv[i], "-iv")) {
			i++;
			if (i == argc)
				errx(1, "-iv: missing file name");
			iv = read_file(argv[i], &iv_size);
			assert(iv);
		}
		if (!strcmp(argv[i], "-tag")) {
			i++;
			if (i == argc)
				errx(1, "-tag: missing file name");
			tag = read_file(argv[i], &tag_size);
			if (tag_size != 16)
				errx(1, "-tag: tag size has to be 16 bytes");
			assert(tag);
		}
	}
	if (!in_size)
		errx(1, "missing or empty input file (-in)");
	if (!key_size)
		errx(1, "missing key (-key)");
	if (!iv_size)
		errx(1, "missing or empty IV file (-iv)");
	if (!tag_size)
		errx(1, "missing or empty tag file (-tag)");
	out = malloc(in_size);
	if (!out)
		errx(1, "out of memory");

	VV(printf("Key is:\n"););
	VV(BIO_dump_fp(stdout, key, key_size););
	VV(printf("IV is:\n"););
	VV(BIO_dump_fp(stdout, iv, iv_size););
	VV(printf("Tag is:\n"););
	VV(BIO_dump_fp(stdout, tag, tag_size););
	VV(printf("Ciphertext:\n"););
	VV(BIO_dump_fp(stdout, out, out_size););

	out_size = decrypt(in, in_size, "", 0, tag, key, iv, iv_size, out);
	if (out_size != in_size)
	       errx(1, "Decrypt failed");	

	VV(printf("Decrypted text:\n"););
	VV(BIO_dump_fp(stdout, out, out_size););

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-out")) {
			i++;
			if (i == argc)
				errx(1, "-out: missing file name");
			write_file(argv[i], out, out_size);
		}
	}

	free(in);
	free(out);
	free(key);
	free(iv);
	free(tag);
}

int main(int argc, char *argv[])
{
	int i;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();	 

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v"))
			verbose++;
		if (!strcmp(argv[i], "-h"))
			usage(argv[0]);
	}

	if (argc < 2)
		usage(argv[0]);

	if (!strcmp(argv[1], "enc"))
		encode_wrapper(argc - 2, &argv[2]);
	else if (!strcmp(argv[1], "dec"))
		decode_wrapper(argc - 2, &argv[2]);
	else
		usage(argv[0]);

	return 0;
}
