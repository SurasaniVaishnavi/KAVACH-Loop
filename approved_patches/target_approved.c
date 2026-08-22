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
     * Reject input that cannot fit inside name, including
     * the required null terminator.
     */
    if ((size_t)bytes_read >= sizeof(name)) {
        fprintf(stderr, "Error: input is too long\n");
        return 1;
    }

    memcpy(name, input, (size_t)bytes_read);
    name[bytes_read] = '\0';

    printf("Hello, %s\n", name);
    return 0;
}