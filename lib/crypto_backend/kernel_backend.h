#ifndef _KERNEL_BACKEND_H
#define _KERNEL_BACKEND_H
int crypt_kernel_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length);

void crypt_kernel_cipher_destroy(struct crypt_cipher *ctx);

int crypt_kernel_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);
int crypt_kernel_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);
#endif
