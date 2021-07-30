#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

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