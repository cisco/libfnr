/*
 * @pyav : Application to test date-time string encryption in fnr mode.
 * 		   The format of the date in provided file should be as following:
 * 				2004-09-16T23:59:58
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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
	int flag = FALSE;
	int yr;
	int mn;
	int dt;
	int hr;
	int min;
	int sec;

	char *string = NULL;
	char *passwd = NULL;
	char *tweak_str = NULL;
	char *filename = NULL;

	clock_t start;
	clock_t end;
	double cpu_time;
	time_t t_of_day;
	time_t raw_data;
	time_t encrypted_data;
	struct tm t;
	FILE * stream = NULL;
	static unsigned char orig_key[32] = {0};

	fnr_expanded_key *key = NULL;
	fnr_expanded_tweak tweak;

	if (argc != ARGS_LIST_COUNT) {
		fprintf (stderr, "Usage: ./test/stringtest -p <password> -t <tweak> "
				"-f <filename>\n");
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
				return FAILURE;
		}
	}

	stream = fopen (filename, "r");
	if (stream == NULL) {
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	FNR_init ();	

	if (generate_master_key (passwd, (char *) orig_key) == 0) {
		fprintf (stderr, "Key derivation function failed\n");
		fclose (stream);
		return FAILURE;
	}

	start = clock();
	if (start == -1) {
		flag = TRUE;
	}

	printf ("\n");
	while (fscanf (stream, "%d-%d-%dT%d:%d:%d",
				&yr, &mn, &dt, &hr, &min, &sec) != EOF) {
		t.tm_year = yr - 1900;
		t.tm_mon = mn - 1;
		t.tm_mday = dt;
		t.tm_hour = hr;
		t.tm_min = min;
		t.tm_sec = sec;
		t.tm_isdst = 0;

		t_of_day = mktime (&t);
		if (t_of_day == -1) {
			perror ("mktime");
			fclose (stream);
			return FAILURE;
		}
		printf ("Date: %s", ctime (&t_of_day));
		printf ("Epoch value: %ld\n", t_of_day);

		key = FNR_expand_key (orig_key, AES_KEY_SIZE, 
				NUM_BITS * sizeof (t_of_day));
		if (key == NULL) {
			fprintf (stderr, "Error expanding key\n");
			fclose (stream);
			return FAILURE;
		}

		FNR_expand_tweak (&tweak, key, (void *) tweak_str, strlen (tweak_str));

		raw_data = t_of_day;
		FNR_encrypt (key, &tweak, &raw_data, &encrypted_data);
		printf ("Encrypted data: %ld\n", encrypted_data);
		printf ("Encrypted date string: %s", ctime (&encrypted_data));

		FNR_decrypt (key, &tweak, &encrypted_data, &raw_data);
		printf ("Decrypted data: %ld\n", raw_data);
		printf ("Date: %s\n", ctime (&raw_data));
	}

	end = clock();
	if ((end != -1) && (flag == FALSE)) {
		cpu_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		printf ("cpu time used: %.3f seconds.\n\n", cpu_time);
	} else {
		printf ("Could not calculate processor time.\n\n");
	}

	fclose (stream);
	FNR_release_key (key);
	FNR_shut ();
	return SUCCESS;
} 

/*
 * End of my codes. 
 */

