#ifndef __PARSER_H
#define __PARSER_H

#include <stddef.h>
#include <stdbool.h>

enum types {
    NUMERIC,
    ALPHA
};

/**
 * @brief This function shall get field from a file that is constructed as /proc/<pid>/status
 *
 * @param[in] haystack      buffer get the data from it
 * @param[in] needle        the key to look
 * @param[in] size          buffer size
 * @param[in] word_counter  after finding the key, which word to return
 * @param[in] type          type of the result [NUMERIC/ALPH]
 *
 * @returns the value from the key
*/
long get_field(char *haystack,
              char *needle,
              size_t size,
              unsigned int word_counter,
              enum types type);

/**
 * @brief this function verifies if string is numeric
 *
 * @param[in] str null termintated string
 *
 * @returns true if numeric, else false
*/
bool is_numeric_str(char *str);

/**
 * @brief reads file and store it in buffer
 *
 * @param[in] path   path to the file
 * @param[in] buffer stores the file in the buffer
 * @param[in] size   size of the buffer
 *
 * @returns true for success, else false
*/
bool read_file(char *path, char *buffer, size_t size);

/**
 * @brief get the n'th word, words cat be seperated using any
 * kind of space (isspace)
 *
 * @param[in] str null terminated string
 * @param[in] n   word number starting from 1
 *
 * @returns pointer to the start of the n'th word
*/
char* get_nth_word(char *str, unsigned int n);
#endif