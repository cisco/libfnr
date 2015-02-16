#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main (int argc, char *argv[])
{
	int yr, mn, dt, hr, min, sec;
	struct tm t;
	time_t t_of_day;

	FILE * stream = fopen ("/home/anand/Desktop/libfnr/libfnr/test/file_string_time", "r");
	if (stream == NULL) {
		perror ("fopen");
		return 1;
	}

	//while (getline (&string, &len, stream) != -1) {
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
		printf ("epoch value: %ld, size = %d\n", t_of_day, sizeof (t_of_day));
	}

	fclose (stream);
	return 0;
}

