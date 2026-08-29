#include <stdio.h>

int main(void)
{
    char name[32];

    printf("Enter your name: ");

    if (fgets(name, sizeof(name), stdin) == NULL) {
        fprintf(stderr, "Error: input could not be read\n");
        return 1;
    }

    printf("Hello, %s", name);
    return 0;
}