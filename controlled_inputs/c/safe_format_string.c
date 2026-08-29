#include <stdio.h>

int main(void)
{
    char input[64];

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    printf("%s", input);
    return 0;
}
