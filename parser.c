#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "parser.h"

static char* get_next_word(char *str) {
    while(!isspace(*str)) { //TODO: replace with isspace
        str++;
    }
    return *str == '\0' ? NULL : str + 1;
}

char* get_nth_word(char *str, unsigned int n)
{
    char *word = str;

    if (n <= 0) {
        return NULL;
    }

    while(word && n - 1 != 0) {
        word = get_next_word(word);
        --n;
    }

    return word;
}



long get_field(char *haystack, char *needle, size_t size, unsigned int word_counter, enum types type) {
    char *runner = strstr(haystack, needle);
    long numeric;

    if (!runner) {
        return -1;
    }

    runner += size;
    runner = get_nth_word(runner, word_counter);
    if (!runner) {
        return -1;
    }

    if (type == NUMERIC) {
        errno = 0;
        numeric = strtol(runner, NULL, 10);
        if (errno) {
            return -1;
        }

        return numeric;
    }

    return runner[0];
}

bool read_file(char *path, char *buffer, size_t size)
{
    FILE *handle;
    int bytes;

    handle = fopen(path, "r");
    if (!handle) {
        printf("couldn't open: %s\n", path);
        return false;
    }

    bytes = fread(buffer,
                  1,
                  size,
                  handle);

    if (bytes < 0) {
        printf("fread opration failed\n");
        return false;
    }

    buffer[bytes] = '\0';

    fclose(handle);
    return true;
}

bool is_numeric_str(char *str) {

    while(*str != '\0') {
        if (!isdigit(*str)) {
            return false;
        }
        ++str;
    }
    return true;
}
