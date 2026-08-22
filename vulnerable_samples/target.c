#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char input[256] = {0};
    char name[32];

    ssize_t bytes_read = read(STDIN_FILENO, input, sizeof(input) - 1);

    if (bytes_read <= 0) {
        return 0;
    }

    input[bytes_read] = '\0';

    /*
     * Intentionally vulnerable for the controlled KAVACH-Loop PoC:
     * input can hold more data than name, and strcpy does not
     * check whether the destination is large enough.
     */
    strcpy(name, input);

    printf("Hello, %s\n", name);
    return 0;
}