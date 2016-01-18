/*
*    libFNR - A reference implementation library for FNR encryption mode.
*
*    FNR represents "Flexible Naor and Reingold" mode
*
*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.
*
*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    Copyright (C) 2014-2015, Cisco Systems, Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/

/*
 * @mgurevin : This is a simple benchmark functions for encryprion and decryption methods.
 */

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "fnr.h"

static double get_time()
{
    struct timeval t;
    struct timezone tzp;

    gettimeofday(&t, &tzp);

    return t.tv_sec + (t.tv_usec * 1e-6);
}

void print_hex(const unsigned char *data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++)
    {
        if (i > 0) {
            printf(":");
        }

        printf("%02X", data[i]);
    }
}

int main (int argc, char *argv[])
{
	int i;
    char *passphrase = NULL;
    char *salt = NULL;
    char *tweak_str = NULL;
    int block_size = -1;
    int iterations = -1;
    static unsigned char aes_key[16];
    unsigned char encrypted[16];

    unsigned char raw[] = { 0x56, 0x9c, 0x3c, 0x57, 0xb3, 0x09, 0xdb, 0xba, 0x59, 0x65, 0x35, 0xff, 0xb5, 0x7c, 0x5a, 0x24 };

	while ((i = getopt(argc, argv, "p:s:t:b:i:")) != -1) {
		switch (i) {
            case 'p':
                passphrase = optarg;
                break;

            case 's':
                salt = optarg;
                break;

			case 't':
				tweak_str = optarg;
				break;

			case 'b':
				block_size = atoi(optarg);
				break;

			case 'i':
				iterations = atoi(optarg);
				break;

			default:
				fprintf(stderr, "Usage: %s -p <passphrase> -s <salt> -t <tweak> -b <block-size> -i <iterations>\n", argv[0]);
				return EXIT_FAILURE;
		}
	}

    if (passphrase == NULL | salt == NULL | tweak_str == NULL | block_size == -1 | iterations == -1) {
        fprintf(stderr, "Usage: %s -p <passphrase> -s <salt> -t <tweak> -b <block-size> -i <iterations>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Passphrase: %s (", passphrase); print_hex(passphrase, strlen(passphrase)); printf(")\n");
    printf("Salt      : %s (", salt); print_hex(salt, strlen(salt)); printf(")\n");
    printf("Tweak     : %s (", tweak_str); print_hex(tweak_str, strlen(tweak_str)); printf(")\n");
    printf("numBits   : %d\n", block_size);
    printf("Iterations: %d\n", iterations);
    printf("-----------------------------------------------------------\n");

    if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char *) salt, strlen(salt), 1000, 128, aes_key) != 1) {
        fprintf(stderr, "Generating PBKDF2 AES key has been failed.\n");
        return EXIT_FAILURE;
    }

    printf("AES Key   : "); print_hex(aes_key, 16); printf("\n");
    printf("RAW Data  : "); print_hex(raw, 16); printf("\n");

    FNR_init();

    fnr_expanded_key *key = FNR_expand_key(aes_key, 128, block_size);
    if (!key) {
        fprintf(stderr, "Expanding AES key has been failed.\n");
        FNR_shut();
        return EXIT_FAILURE;
    }

    fnr_expanded_tweak tweak;
    FNR_expand_tweak(&tweak, key, (void*) tweak_str, strlen(tweak_str));

    FNR_burn(encrypted, 16);
    FNR_encrypt(key, &tweak, &raw, &encrypted);
    printf("Encrypted : "); print_hex(encrypted, 16); printf("\n");
    printf("-----------------------------------------------------------\n");


    printf("Begin encryption benchmark...");
    double begin = get_time();
    for (i = 0; i < iterations; i++) {
        FNR_encrypt(key, &tweak, &raw, &encrypted);
    }
    double elapsed = get_time() - begin;
    printf(" Completed.\n");

    double tp_encryption = iterations / elapsed;

    printf("Begin decryption benchmark... ");
    begin = get_time();
    for (i = 0; i < iterations; i++) {
        FNR_decrypt(key, &tweak, &encrypted, &raw);
    }
    elapsed = get_time() - begin;
    printf("Completed.\n\n");

    double tp_decryption = iterations / elapsed;

    printf("Encryption: %f ops/s\n", tp_encryption);
    printf("Decryption: %f ops/s\n", tp_decryption);

    FNR_release_key(key);
    FNR_shut();

	return EXIT_SUCCESS;
} 