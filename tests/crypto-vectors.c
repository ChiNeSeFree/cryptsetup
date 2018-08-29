/*
 * cryptsetup crypto backend test vectors
 *
 * Copyright (C) 2018, Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "crypto_backend.h"

#define MAX_BLOCK_SIZE 128

static void printhex(const char *s, const char *buf, size_t len)
{
	size_t i;

	printf("%s: ", s);
	for (i = 0; i < len; i++)
		printf(" %02x", (unsigned char)buf[i]);
	printf("\n");
	fflush(stdout);
}

/*
 * KDF tests
 */
struct kdf_test_vector {
	const char *type;
	const char *hash;
	unsigned int hash_block_length;
	unsigned int iterations;
	unsigned int memory;
	unsigned int parallelism;
	const char *password;
	unsigned int password_length;
	const char *salt;
	unsigned int salt_length;
//	const char *key;
//	unsigned int key_length;
//	const char *ad;
//	unsigned int ad_length;
	const char *output;
	unsigned int output_length;
};

struct kdf_test_vector kdf_test_vectors[] = {
	/* Argon2 RFC (without key and ad values) */
	{
		"argon2i", NULL, 0, 3, 32, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
//		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
//		"\x04\x04\x04\x04\x04\x04\x04\x04"
//		"\x04\x04\x04\x04", 12,
		"\xa9\xa7\x51\x0e\x6d\xb4\xd5\x88"
		"\xba\x34\x14\xcd\x0e\x09\x4d\x48"
		"\x0d\x68\x3f\x97\xb9\xcc\xb6\x12"
		"\xa5\x44\xfe\x8e\xf6\x5b\xa8\xe0", 32
//		"\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa"
//		"\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
//		"\xc8\xde\x6b\x01\x6d\xd3\x88\xd2"
//		"\x99\x52\xa4\xc4\x67\x2b\x6c\xe8", 32
	},
	{
		"argon2id", NULL, 0, 3, 32, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
//		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
//		"\x04\x04\x04\x04\x04\x04\x04\x04"
//		"\x04\x04\x04\x04", 12,
		"\x03\xaa\xb9\x65\xc1\x20\x01\xc9"
		"\xd7\xd0\xd2\xde\x33\x19\x2c\x04"
		"\x94\xb6\x84\xbb\x14\x81\x96\xd7"
		"\x3c\x1d\xf1\xac\xaf\x6d\x0c\x2e", 32
//		"\x0d\x64\x0d\xf5\x8d\x78\x76\x6c"
//		"\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
//		"\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e"
//		"\xb5\x25\x20\xe9\x6b\x01\xe6\x59", 32
	},
	/* RFC 3962 */
	{
		"pbkdf2", "sha1", 64, 1, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\xcd\xed\xb5\x28\x1b\xb2\xf8\x01"
		"\x56\x5a\x11\x22\xb2\x56\x35\x15"
		"\x0a\xd1\xf7\xa0\x4b\xb9\xf3\xa3"
		"\x33\xec\xc0\xe2\xe1\xf7\x08\x37", 32
	}, {
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x01\xdb\xee\x7f\x4a\x9e\x24\x3e"
		"\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
		"\xa0\x53\x78\xb9\x32\x44\xec\x8f"
		"\x48\xa9\x9e\x61\xad\x79\x9d\x86", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e"
		"\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
		"\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f"
		"\x70\x8a\x31\xe2\xe6\x2b\x1e\x13", 32
	}, {
		"pbkdf2", "sha1", 64, 5, 0, 0,
		"password", 8,
		"\0224VxxV4\022", 8, // "\x1234567878563412
		"\xd1\xda\xa7\x86\x15\xf2\x87\xe6"
		"\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
		"\x3f\x98\xd2\x03\xe6\xbe\x49\xa6"
		"\xad\xf4\xfa\x57\x4b\x6e\x64\xee", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64,
		"pass phrase equals block size", 29,
		"\x13\x9c\x30\xc0\x96\x6b\xc3\x2b"
		"\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
		"\xc5\xec\x59\xf1\xa4\x52\xf5\xcc"
		"\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\xca\xd6\xd4\x68\x77\x0c\xd5"
		"\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
		"\x1a\x8b\x4d\x28\x26\x01\xdb\x3b"
		"\x36\xbe\x92\x46\x91\x5e\xc8\x2a", 32
	}, {
		"pbkdf2", "sha1", 64, 50, 0, 0,
		"\360\235\204\236", 4, // g-clef ("\xf09d849e)
		"EXAMPLE.COMpianist", 18,
		"\x6b\x9c\xf2\x6d\x45\x45\x5a\x43"
		"\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
		"\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2"
		"\x81\xff\x30\x69\xe1\xe9\x4f\x52", 32
	}, {
	/* RFC-6070 */
		"pbkdf2", "sha1", 64, 1, 0, 0,
		"password", 8,
		"salt", 4,
		"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9"
		"\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6", 20
	}, {
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"password", 8,
		"salt", 4,
		"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e"
		"\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57", 20
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"password", 8,
		"salt", 4,
		"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad"
		"\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1", 20
	}, {
		"pbkdf2", "sha1", 64, 16777216, 0, 0,
		"password", 8,
		"salt", 4,
		"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94"
		"\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84", 20
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
		"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
		"\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
		"\x4c\xf2\xf0\x70\x38", 25
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"pass\0word", 9,
		"sa\0lt", 5,
		"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37"
		"\xd7\xf0\x34\x25\xe0\xc3", 16
	}, {
	/* empty password test */
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"", 0,
		"salt", 4,
		"\x13\x3a\x4c\xe8\x37\xb4\xd2\x52\x1e\xe2"
		"\xbf\x03\xe1\x1c\x71\xca\x79\x4e\x07\x97", 20
	}, {
	/* Password exceeds block size test */
		"pbkdf2", "sha256", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x22\x34\x4b\xc4\xb6\xe3\x26\x75"
		"\xa8\x09\x0f\x3e\xa8\x0b\xe0\x1d"
		"\x5f\x95\x12\x6a\x2c\xdd\xc3\xfa"
		"\xcc\x4a\x5e\x6d\xca\x04\xec\x58", 32
	}, {
		"pbkdf2", "sha512", 128, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 129,
		"pass phrase exceeds block size", 30,
		"\x0f\xb2\xed\x2c\x0e\x6e\xfb\x7d"
		"\x7d\x8e\xdd\x58\x01\xb4\x59\x72"
		"\x99\x92\x16\x30\x5e\xa4\x36\x8d"
		"\x76\x14\x80\xf3\xe3\x7a\x22\xb9", 32
	}, {
		"pbkdf2", "whirlpool", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\x1c\x74\xf5\x88\x26\xe7\x6a"
		"\x53\x58\xf4\x0c\x39\xe7\x80\x89"
		"\x07\xc0\x31\x19\x9a\x50\xa2\x48"
		"\xf1\xd9\xfe\x78\x64\xe5\x84\x50", 32
	}
};

/*
 * Hash tests
 */

struct hash_alg {
	const char *name;
	int length;
};

static struct hash_alg hash_algs[] = {
	{ "sha1",       20 },
	{ "sha256",     32 },
	{ "sha512",     64 },
	{ "ripemd160",  20 },
	{ "whirlpool",  64 },
	{ NULL,          0 }
};

struct hash_in {
	const char* buffer;
	unsigned int length;
};

struct hash_in hash_inputs[]
	= { { "", 0 },
		{ "a", 1 },
		{ "abc", 3 },
		{ "abcdefghijklmnopqrstuvwxyz", 26 },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62 },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 },
		{ "message digest", 14 } };

struct hash_out {
	uint32_t crc32_out;
	const char* sha1_out;
	const char* sha256_out;
	const char* sha512_out;
	const char* rmd160_out;
	const char* wp512_out;
};

struct hash_out hash_outputs[] = {
    {
        0x00000000,
        "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09",
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
        "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31",
        "\x19\xfa\x61\xd7\x55\x22\xa4\x66\x9b\x44\xe3\x9c\x1d\x2e\x17\x26\xc5\x30\x23\x21\x30\xd4\x07\xf8\x9a\xfe\xe0\x96\x49\x97\xf7\xa7\x3e\x83\xbe\x69\x8b\x28\x8f\xeb\xcf\x88\xe3\xe0\x3c\x4f\x07\x57\xea\x89\x64\xe5\x9b\x63\xd9\x37\x08\xb1\x38\xcc\x42\xa6\x6e\xb3"
    },
    {
        0xe8b7be43,
        "\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc\xe1\x5d\x1d\xdc\xb9\xea\xea\xea\x37\x76\x67\xb8",
        "\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb",
        "\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82\xf2\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0\x5a\xbc\x54\xd0\x56\x0e\x0f\x53\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02\x52\xaa\x5e\x74\x21\x05\x46\xf3\x69\xfb\xbb\xce\x8c\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75",
        "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe",
        "\x8a\xca\x26\x02\x79\x2a\xec\x6f\x11\xa6\x72\x06\x53\x1f\xb7\xd7\xf0\xdf\xf5\x94\x13\x14\x5e\x69\x73\xc4\x50\x01\xd0\x08\x7b\x42\xd1\x1b\xc6\x45\x41\x3a\xef\xf6\x3a\x42\x39\x1a\x39\x14\x5a\x59\x1a\x92\x20\x0d\x56\x01\x95\xe5\x3b\x47\x85\x84\xfd\xae\x23\x1a"
    },
    {
        0x352441c2,
        "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d",
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
        "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f",
        "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc",
        "\x4e\x24\x48\xa4\xc6\xf4\x86\xbb\x16\xb6\x56\x2c\x73\xb4\x02\x0b\xf3\x04\x3e\x3a\x73\x1b\xce\x72\x1a\xe1\xb3\x03\xd9\x7e\x6d\x4c\x71\x81\xee\xbd\xb6\xc5\x7e\x27\x7d\x0e\x34\x95\x71\x14\xcb\xd6\xc7\x97\xfc\x9d\x95\xd8\xb5\x82\xd2\x25\x29\x20\x76\xd4\xee\xf5"
    },
    {
        0x4c2750bd,
        "\x32\xd1\x0c\x7b\x8c\xf9\x65\x70\xca\x04\xce\x37\xf2\xa1\x9d\x84\x24\x0d\x3a\x89",
        "\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73",
        "\x4d\xbf\xf8\x6c\xc2\xca\x1b\xae\x1e\x16\x46\x8a\x05\xcb\x98\x81\xc9\x7f\x17\x53\xbc\xe3\x61\x90\x34\x89\x8f\xaa\x1a\xab\xe4\x29\x95\x5a\x1b\xf8\xec\x48\x3d\x74\x21\xfe\x3c\x16\x46\x61\x3a\x59\xed\x54\x41\xfb\x0f\x32\x13\x89\xf7\x7f\x48\xa8\x79\xc7\xb1\xf1",
        "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb\xdc\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc",
        "\xf1\xd7\x54\x66\x26\x36\xff\xe9\x2c\x82\xeb\xb9\x21\x2a\x48\x4a\x8d\x38\x63\x1e\xad\x42\x38\xf5\x44\x2e\xe1\x3b\x80\x54\xe4\x1b\x08\xbf\x2a\x92\x51\xc3\x0b\x6a\x0b\x8a\xae\x86\x17\x7a\xb4\xa6\xf6\x8f\x67\x3e\x72\x07\x86\x5d\x5d\x98\x19\xa3\xdb\xa4\xeb\x3b"
    },
    {
        0x1fc2e6d2,
        "\x76\x1c\x45\x7b\xf7\x3b\x14\xd2\x7e\x9e\x92\x65\xc4\x6f\x4b\x4d\xda\x11\xf9\x40",
        "\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0",
        "\x1e\x07\xbe\x23\xc2\x6a\x86\xea\x37\xea\x81\x0c\x8e\xc7\x80\x93\x52\x51\x5a\x97\x0e\x92\x53\xc2\x6f\x53\x6c\xfc\x7a\x99\x96\xc4\x5c\x83\x70\x58\x3e\x0a\x78\xfa\x4a\x90\x04\x1d\x71\xa4\xce\xab\x74\x23\xf1\x9c\x71\xb9\xd5\xa3\xe0\x12\x49\xf0\xbe\xbd\x58\x94",
        "\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed\x3a\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89",
        "\xdc\x37\xe0\x08\xcf\x9e\xe6\x9b\xf1\x1f\x00\xed\x9a\xba\x26\x90\x1d\xd7\xc2\x8c\xde\xc0\x66\xcc\x6a\xf4\x2e\x40\xf8\x2f\x3a\x1e\x08\xeb\xa2\x66\x29\x12\x9d\x8f\xb7\xcb\x57\x21\x1b\x92\x81\xa6\x55\x17\xcc\x87\x9d\x7b\x96\x21\x42\xc6\x5f\x5a\x7a\xf0\x14\x67"
    },
    {
        0x171a3f5f,
        "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1",
        "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
        "\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45",
        "\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0\x6c\x27\xdc\xf4\x9a\xda\x62\xeb\x2b",
        "\x52\x6b\x23\x94\xd8\x56\x83\xe2\x4b\x29\xac\xd0\xfd\x37\xf7\xd5\x02\x7f\x61\x36\x6a\x14\x07\x26\x2d\xc2\xa6\xa3\x45\xd9\xe2\x40\xc0\x17\xc1\x83\x3d\xb1\xe6\xdb\x6a\x46\xbd\x44\x4b\x0c\x69\x52\x0c\x85\x6e\x7c\x6e\x9c\x36\x6d\x15\x0a\x7d\xa3\xae\xb1\x60\xd1"
    },
    {
        0x20159d7f,
        "\xc1\x22\x52\xce\xda\x8b\xe8\x99\x4d\x5f\xa0\x29\x0a\x47\x23\x1c\x1d\x16\xaa\xe3",
        "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50",
        "\x10\x7d\xbf\x38\x9d\x9e\x9f\x71\xa3\xa9\x5f\x6c\x05\x5b\x92\x51\xbc\x52\x68\xc2\xbe\x16\xd6\xc1\x34\x92\xea\x45\xb0\x19\x9f\x33\x09\xe1\x64\x55\xab\x1e\x96\x11\x8e\x8a\x90\x5d\x55\x97\xb7\x20\x38\xdd\xb3\x72\xa8\x98\x26\x04\x6d\xe6\x66\x87\xbb\x42\x0e\x7c",
        "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36",
        "\x37\x8c\x84\xa4\x12\x6e\x2d\xc6\xe5\x6d\xcc\x74\x58\x37\x7a\xac\x83\x8d\x00\x03\x22\x30\xf5\x3c\xe1\xf5\x70\x0c\x0f\xfb\x4d\x3b\x84\x21\x55\x76\x59\xef\x55\xc1\x06\xb4\xb5\x2a\xc5\xa4\xaa\xa6\x92\xed\x92\x00\x52\x83\x8f\x33\x62\xe8\x6d\xbd\x37\xa8\x90\x3e"
    }
};

/*
 * HMAC tests
 */
// RFC 4231 - HMAC test vectors for SHA-256, SHA-512
// RFC 2202 - HMAC test vectors for SHA-1

struct hmac_test_vector {
	const char *key;
	unsigned int key_length;
	const char *data;
	unsigned int data_length;
	const char *hmac_sha_1;
	const char *hmac_sha_256;
	const char *hmac_sha_512;
};

struct hmac_test_vector hmac_test_vectors[] = {
	{
		"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
		"\x48\x69\x20\x54\x68\x65\x72\x65", 8, // "Hi There"
		"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00",
		"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
		"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54"
	},
	{
		"\x4a\x65\x66\x65", 4, // "Jefe"
		"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28, // "what do ya want for nothing?"
		"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79",
		"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43",
		"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37"
	},
	{
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3",
		"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe",
		"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb"
	},
	{
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50,
		"\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda",
		"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b",
		"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd"
	},
	{
		// Long key
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131,
		"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74", 54, // "Test Using Larger Than Block-Size Key - Hash Key First"
		"\x90\xd0\xda\xce\x1c\x1b\xdc\x95\x73\x39\x30\x78\x03\x16\x03\x35\xbd\xe6\xdf\x2b",
		"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54",
		"\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98"
	},
	{
		// Long key and long data
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131,
		"\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e", 152,
		"\x21\x7e\x44\xbb\x08\xb6\xe0\x6a\x2d\x6c\x30\xf3\xcb\x9f\x53\x7f\x97\xc6\x33\x56",
		"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2",
		"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58"
	}
};

static int pbkdf_test_vectors(void)
{
	char result[256];
	unsigned int i;
	struct kdf_test_vector *vec;

	for (i = 0; i < (sizeof(kdf_test_vectors) / sizeof(*kdf_test_vectors)); i++) {
		vec = &kdf_test_vectors[i];
		printf("PBKDF vector %02d %s ", i, vec->type);
		if (crypt_pbkdf(vec->type, vec->hash,
		    vec->password, vec->password_length,
		    vec->salt, vec->salt_length,
		    result, vec->output_length,
		    vec->iterations, vec->memory, vec->parallelism)) {
			printf("crypto backend [FAILED].\n");
			return -EINVAL;
		}
		if (memcmp(result, vec->output, vec->output_length)) {
			printf("expected output [FAILED].\n");
			printhex(" got", result, vec->output_length);
			printhex("want", vec->output, vec->output_length);
			return -EINVAL;
		}
		printf("[OK]\n");
		memset(result, 0, sizeof(result));
	}
	return 0;
}


const char* get_vec(struct hash_out* out, int i)
{
	switch (i) {
	case 0:
		return out->sha1_out;
	case 1:
		return out->sha256_out;
	case 2:
		return out->sha512_out;
	case 3:
		return out->rmd160_out;
	case 4:
		return out->wp512_out;
	}

	return NULL;
}

static int hash_test(void)
{
	uint32_t crc32;
	unsigned int i, j;
	int r, hash_length;
	struct hash_in* in_vec;
	struct hash_out* out_vec;
	struct hash_alg* hash;
	struct crypt_hash *h;
	char result[64];

	for (i = 0; i < (sizeof(hash_inputs) / sizeof(*hash_inputs)); i++) {
		in_vec  = &hash_inputs[i];
		out_vec = &hash_outputs[i];

		// CRC32 vector test
		printf("Hash vector %02d: [CRC32]", i);
		crc32 = crypt_crc32(~0, in_vec->buffer, in_vec->length) ^ ~0;
		if (crc32 != out_vec->crc32_out) {
			printf("expected output [FAILED].\n");
			printf(" got: %x\n", crc32);
			printf("want: %x\n", out_vec->crc32_out);
			return -EINVAL;
		}

		// Other hashes test
		for (j = 0; j < (sizeof(hash_algs) / sizeof(*hash_algs) - 1); j++) {
			hash = &hash_algs[j];

			hash_length = crypt_hash_size(hash->name);
			if (hash_length != hash->length) {
				if (hash_length < 0) {
					printf("[%s N/A]", hash->name);
					continue;
				}
				return -EINVAL;
			}

			printf("[%s]", hash->name);
			if (crypt_hash_init(&h, hash->name))
				return -EINVAL;

			r = crypt_hash_write(h, in_vec->buffer, in_vec->length);

			if (!r)
				r = crypt_hash_final(h, result, hash->length);

			crypt_hash_destroy(h);

			if (r)
				return r;

			if (memcmp(result, get_vec(out_vec, j), hash->length)) {
				printf("expected output [FAILED].\n");
				printhex(" got", result, hash->length);
				printhex("want", get_vec(out_vec, j), hash->length);
				return -EINVAL;
			}
		}

		printf("\n");
	}

	return 0;
}

const char* get_hmac_res(struct hmac_test_vector* out, int i)
{
	switch (i) {
	case 0:
		return out->hmac_sha_1;
	case 1:
		return out->hmac_sha_256;
	case 2:
		return out->hmac_sha_512;
	}

	return NULL;
}


static int hmac_test(void)
{
	struct crypt_hmac *hmac;
	struct hmac_test_vector *vector;
	struct crypt_hash *h;
	unsigned int hmac_length;
	int i, j, r;

	char result[64];
	char key[MAX_BLOCK_SIZE];

	for (i = 0; i < (sizeof(hmac_test_vectors) / sizeof(*hmac_test_vectors)); i++) {
		vector = &hmac_test_vectors[i];
		printf("HMAC vector %02d: ", i);

		for(j = 0; j < 3; j++) {
			struct hash_alg* hash = &hash_algs[j];
			hmac_length = crypt_hmac_size(hash->name);
			if (hmac_length != hash->length) {
				if (hmac_length < 0) {
					printf("[%s N/A]", hash->name);
					continue;
				}
				return -EINVAL;
			}
			printf("[%s]", hash->name);

			int key_length = vector->key_length;

			// hash key first if key size is greater than max block size
			if (key_length > MAX_BLOCK_SIZE) {
				if (crypt_hash_init(&h, hash->name))
				return -EINVAL;

				r = crypt_hash_write(h, vector->key, vector->key_length);

				if (!r)
					r = crypt_hash_final(h, key, hash->length);

				crypt_hash_destroy(h);

				if (r)
					return r;

				key_length = hash->length;
			} else {
				memcpy(key, vector->key, vector->key_length);
			}

			if (crypt_hmac_init(&hmac, hash->name, key, key_length))
				return -EINVAL;

			r = crypt_hmac_write(hmac, vector->data, vector->data_length);

			if (!r)
				r = crypt_hmac_final(hmac, result, hmac_length);

			crypt_hmac_destroy(hmac);

			if (r)
				return r;

			if (memcmp(result, get_hmac_res(vector, j), hash->length)) {
				printf("expected output [FAILED].\n");
				printhex(" got", result, hash->length);
				printhex("want", get_hmac_res(vector, j), hash->length);
				return -EINVAL;
			}
		}
		printf("\n");
	}
}

int main(int argc, char *argv[])
{
	if (crypt_backend_init(NULL)) {
		printf("Crypto backend init error.\n");
		exit(EXIT_FAILURE);
	}
	printf("Test vectors using %s crypto backend.\n", crypt_backend_version());

	if (pbkdf_test_vectors())
		exit(EXIT_FAILURE);

	if (hash_test())
		exit(EXIT_FAILURE);

	if (hmac_test())
		exit(EXIT_FAILURE);

	crypt_backend_destroy();
	exit(EXIT_SUCCESS);
}
