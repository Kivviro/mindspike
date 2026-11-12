#include <stdio.h>
#include <string.h>

int main()
{
	char name[100];

	if (fgets(name, sizeof name, stdin) != NULL)
	{
		size_t len = strlen(name);
		name[len - 1] = '\0';

		printf("Hello %s!", name);
	}

	return 0;
}