#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// https://stackoverflow.com/questions/29242/off-the-shelf-c-hex-dump-code
void hexdump(const char* caption, void* ptr, int buflen) {
    printf("%s\n", caption);
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

void dump_to_file(const char* name, void* data, size_t size) {
    auto* output = fopen(name, "wb");
    if (!output) {
        printf("failed to open output\n");
        exit(1);
    }
    fwrite(data, size, 1, output);
    fclose(output);
}

#ifndef memmem
// https://stackoverflow.com/questions/52988769/writing-own-memmem-for-windows
void* memmem(void* haystack, size_t haystack_len, void* needle, size_t needle_len) {
    if (haystack == NULL) return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL; // or assert(needle != NULL);
    if (needle_len == 0) return NULL;

    for (const char* h = (const char*)haystack;
        haystack_len >= needle_len;
        ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) {
            return (void*)h;
        }
    }
    return NULL;
}
#endif