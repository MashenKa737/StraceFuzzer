#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

int main(void) {
	char buffer[sizeof("Hello\n")];
	FILE * in = NULL, * out = NULL;

	out = fopen("text.txt", "w");
	fprintf(out, "Hello\n");
	fclose(out);

	in = fopen("text.txt", "r");
	fscanf(in, "%s", buffer);
	fclose(in);

	printf("%s\n", buffer);
	return 0;
}
