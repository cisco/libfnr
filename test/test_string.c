/*
 * @pyav : App to test short string encryption in fnr mode
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <time.h>
#include "fnr.h"

#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define FAILURE 1
#define KEYLEN 16
#define NUM_BITS 8
#define MAX_BYTES 16
#define ITERATION 1000
#define AES_KEY_SIZE 128
#define MAX_DATA_LEN 1024
#define ARGS_LIST_COUNT 7

#define FREE_STRING \
	if (string != NULL) {\
		free (string); \
		string = NULL; \
	}

#define FREE_RAW_DATA \
	if (raw_data != NULL) { \
		free (raw_data); \
		raw_data = NULL; \
	}

#define FREE_ENCRYPTED_DATA \
	if (encrypted_data != NULL) { \
		free (encrypted_data); \
		encrypted_data = NULL; \
	} 

static int generate_master_key (char *passwd, char *key) 
{
	unsigned char salt[16];

	if (!(RAND_bytes (salt, sizeof (salt)))) {
		fprintf (stderr, "Call to %s failed\n", __func__);
		return 0; /* 0 designates error here */
	}

	return (PKCS5_PBKDF2_HMAC_SHA1(passwd, strlen (passwd), 
				(unsigned char *) salt, strlen (salt), ITERATION, KEYLEN, key));
}

int main (int argc, char *argv[])
{
	int c;
	int count = 0;
	int flag = FALSE;

	size_t len = 0;
	size_t str_len;
	ssize_t read;
	clock_t start;
	clock_t end;
	double cpu_time;

	char *string = NULL;
	char *passwd = NULL;
	char *tweak_str = NULL;
	char *filename = NULL;
	char *raw_data = NULL;
	char *encrypted_data = NULL;

	FILE * stream = NULL;
	static unsigned char orig_key[32] = {0};

	fnr_expanded_key *key = NULL;
	fnr_expanded_tweak tweak;

	if (argc != ARGS_LIST_COUNT) {
		fprintf (stderr, "Usage: ./test/stringtest -p <password> -t <tweak> "
				"-f <filename>\n");
		return FAILURE;
	}

	encrypted_data = (char *) calloc (MAX_DATA_LEN + 1, sizeof (char));
	if (encrypted_data == NULL) {
		fprintf (stderr, "Error allocating memory for encrypted_data.\n");
		return FAILURE;
	}

	raw_data = (char *) calloc (MAX_DATA_LEN + 1, sizeof (char));
	if (raw_data == NULL) {
		fprintf (stderr, "Error allocating memory for raw_data.\n");
		FREE_ENCRYPTED_DATA;
		return FAILURE;
	}

	while ((c = getopt (argc, argv, "p:t:f:")) != -1) {
		switch (c) {
			case 'p':
				passwd = optarg;
				break;

			case 't':
				tweak_str = optarg;
				break;

			case 'f':
				filename = optarg;
				break;

			default:
				fprintf (stderr, "Usage: ./test/stringtest -p <password> -t <tweak> "
						"-f <filename>");
				FREE_ENCRYPTED_DATA;
				FREE_RAW_DATA;
				return FAILURE;
		}
	}

	stream = fopen (filename, "r");
	if (stream == NULL) {
		FREE_ENCRYPTED_DATA;
		FREE_RAW_DATA;
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	FNR_init ();	

	if (generate_master_key (passwd, (char *) orig_key) == 0) {
		fprintf (stderr, "Key derivation function failed\n");
		FREE_ENCRYPTED_DATA;
		FREE_RAW_DATA;
		return FAILURE;
	}

	start = clock();
	if (start == -1) {
		flag = TRUE;
	}

	while ((read = getline (&string, &len, stream)) != -1) {
		count++;
		str_len = strlen (string);
		string[str_len - 1] = '\0';
		str_len--;
		if (str_len > MAX_BYTES) {
			fprintf (stderr, "Cannot encrypt for entry #: %d, "
					"length more than %d bytes.\n", count, MAX_BYTES);
			continue;
		}

		key = FNR_expand_key (orig_key, AES_KEY_SIZE, 
				NUM_BITS * str_len);
		if (key == NULL) {
			fprintf (stderr, "Error expanding key\n");
			FREE_STRING;
			FREE_ENCRYPTED_DATA;
			FREE_RAW_DATA;
			return FAILURE;
		}

		FNR_expand_tweak (&tweak, key, (void *) tweak_str, strlen (tweak_str));

		strcpy (raw_data, string); 
		FNR_encrypt (key, &tweak, raw_data, encrypted_data);
		printf ("Encrypted data: %s\n", encrypted_data);

		FNR_decrypt (key, &tweak, encrypted_data, raw_data);
		printf ("Decrypted data: %s\n", raw_data);
	}

	end = clock();
	if ((end != -1) && (flag == FALSE)) {
		cpu_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		printf ("cpu time used: %.3f seconds.\n", cpu_time);
	} else {
		printf ("Could not calculate processor time.\n");
	}

	FREE_STRING;
	FREE_ENCRYPTED_DATA;
	FREE_RAW_DATA;
	FNR_release_key (key);
	FNR_shut ();
	return SUCCESS;
} 

/*
 * End of my codes. 
 */

