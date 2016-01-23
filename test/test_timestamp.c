/*
 *    libFNR - A reference implementation library for FNR encryption.
 *
 *    FNR represents "Flexible Naor and Reingold" 
 * 
 *    FNR is a small domain block cipher to encrypt small domain
 *    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.
 * 
 *    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
 *
 *    test_timestamp.c is written by Anand Verma [verma.anand09@gmail.com].
 *	  
 *    Thanks to Prakruti C [prak1090@gmail.com] for providing reference 
 *    code in c++ for date format conversions.
 *
 *    Copyright (C) 2014 , Cisco Systems Inc.
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
 */

/*
 * @pyav : Application to test timestamp encryption in fnr mode.
 *         The format of the date in provided file should be as following:
 *         2004-09-16T23:59:58
 */

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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

	char datestr[21] = {0};
	size_t len = 0;
	size_t str_len;
	ssize_t read;
	char *passwd = NULL;
	char *tweak_str = NULL;
	char *filename = NULL;

	clock_t start;
	clock_t end;
	double cpu_time;
	time_t t_of_day;
	time_t time_t_data;
	uint32_t raw_data;
	uint32_t encrypted_data;
	uint32_t time;
	struct tm t;
	FILE * stream = NULL;
	static unsigned char orig_key[32] = {0};

	fnr_expanded_key *key = NULL;
	fnr_expanded_tweak tweak;

	if (argc != ARGS_LIST_COUNT) {
		fprintf (stderr, "Usage: ./test/timestamptest -p <password> -t <tweak> "
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
				fprintf (stderr, "Usage: ./test/timestamptest -p <password> -t <tweak> "
						"-f <filename>");
				return FAILURE;
		}
	}

	stream = fopen (filename, "r");
	if (stream == NULL) {
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	/* Init */
	FNR_init ();	

	if (generate_master_key (passwd, (char *) orig_key) == 0) {
		fprintf (stderr, "Key derivation function failed\n");
		fclose (stream);
		return FAILURE;
	}

	key = FNR_expand_key (orig_key, AES_KEY_SIZE, 
			NUM_BITS * sizeof (t_of_day));
	if (key == NULL) {
		fprintf (stderr, "Error expanding key\n");
		fclose (stream);
		return FAILURE;
	}

	FNR_expand_tweak (&tweak, key, (void *) tweak_str, strlen (tweak_str));

	start = clock();
	if (start == -1) {
		flag = TRUE;
	}

	printf ("\n");
	while (fgets (datestr, sizeof (datestr), stream) != NULL) {
		len = strlen (datestr);
		if ((len != 0) && (datestr[len - 1] == '\n')) {
			datestr[len - 1] = '\0';
			if (sscanf (datestr, "%d-%d-%dT%d:%d:%d", 
						&yr, &mn, &dt, &hr, &min, &sec) != 6) {
				fprintf (stderr, "sscanf didn't read six elements\n");
				continue;
			}
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

			time = htonl ((uint32_t) t_of_day);
			printf ("htonl (t_of_day) = %" PRIu32 "\n", time);

			raw_data = time;
			FNR_encrypt (key, &tweak, &raw_data, &encrypted_data);
			printf ("Encrypted data: %" PRIu32 "\n", encrypted_data);
			time_t_data = (time_t) encrypted_data;
			printf ("Encrypted date string: %s", ctime (&time_t_data));

			FNR_decrypt (key, &tweak, &encrypted_data, &raw_data);
			printf ("Decrypted data: %" PRIu32 "\n", raw_data);
			raw_data = ntohl (raw_data);
			printf ("htonl (raw_data)  = %" PRIu32 "\n", raw_data);
			time_t_data = (time_t) raw_data;
			printf ("Date: %s\n", ctime (&time_t_data));
		} else {
			break;
		}
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

