#pragma once

void hexdump(const char* caption, void* ptr, int buflen);
void dump_to_file(const char* name, void* data, size_t size);