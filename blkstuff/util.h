#pragma once

void hexdump(const char* caption, void* ptr, int buflen);
void dump_to_file(const char* name, void* data, size_t size);
void* memmem(void* haystack, size_t haystack_len, void* needle, size_t needle_len);

#define MAKE_UINT32(a, b1, b2, b3, b4) (uint8_t)a[b1] | ((uint8_t)a[b2] << 8) | ((uint8_t)a[b3] << 16) | ((uint8_t)a[b4] << 24)