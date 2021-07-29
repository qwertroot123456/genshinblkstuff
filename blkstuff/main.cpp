#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <random>

#include "util.h"
#include "magic_constants.h"

// notes are from the genshin impact 1.5 dev build leak UnityEngine.dll (sha256 38399169552791bbfb7b3792dd3e91d3788067e29ffc2437f595060b051d2dd3)

void key_scramble1(uint8_t* key) {
    // UnityPlayer:$1615F0
	for (unsigned i = 0; i < 0x10; i++)
		key[i] = key_scramble_table1[((i & 3) << 8) | key[i]];
}

uint8_t xor_combine(uint8_t* input) {
    // xors an array of 16 bytes into a single byte
    //hexdump(input, 0x10);
    uint8_t ret = 0;
    for (int i = 0; i < 16; i++)
        ret ^= input[i];
    return ret;
}

void create_decrypt_vector(uint8_t* key, uint8_t* encrypted_data, unsigned encrypted_size, uint8_t* output, unsigned output_size) {
    if (output_size != 4096) {
        printf("create_decrypt_vector does not support an output_size other than 4096\n");
        exit(1);
    }

    // TODO: reimplement this properly instead of copy and pasting from decomp
    int v9 = 0;
    int64_t i;
    int64_t v12;
    for (i = -1; ; i = v12) {
        if (v9 >= (int)(encrypted_size >> 3))
            break;
        v12 = ((uint64_t*)encrypted_data)[v9] ^ i;
        ++v9;
    }

    auto* key_qword = (uint64_t*)key;
    // another magic constant, this time from blk_stuff2
    uint64_t seed = key_qword[1] ^ 0x567BA22BABB08098 ^ i ^ key_qword[0];
    printf("seed: 0x%llx\n", seed);

    auto mt_rand = std::mt19937_64(seed);
    for (int i = 0; i < output_size >> 3; i++)
        ((uint64_t*)output)[i] = mt_rand();
}

void key_scramble2(uint8_t* key) {
	// UnityPlayer:$26EA90
    uint8_t expanded_key[256] = {};

    // usually this table gets xor'd against random data that's unique for every run
    // obviously if the random data actually mattered, it would make decryption impossible
    for (int i = 0; i < 16; i++)
        expanded_key[i * 16] = key[i];
    for (int i = 0; i < sizeof(expanded_key); i++)
        expanded_key[i] ^= blk_stuff1_p1[i] ^ stack_stuff[i];

    // should probably be in magic_constants.h, but it's very small
    const uint8_t index_scramble[16] = {
        0,  13, 10, 7,
        4,  1,  14, 11,
        8,  5,  2,  15,
        12, 9,  6,  3
    };
    for (uint64_t i = 1; i < 10; i++) {
        uint32_t scratch[4] = {};
        for (uint64_t j = 0; j < 4; j++) {
            uint8_t temp = 0;
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p2)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 1]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p3)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 2]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p4)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 3]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p5)[temp];
        }
        // also usually xor'd
        memset(expanded_key, 0, sizeof(expanded_key));
        for (uint64_t j = 0; j < 16; j++)
            expanded_key[j * 16] = ((uint8_t*)scratch)[j];
        for (uint64_t j = 0; j < 256; j++) {
            uint64_t v10 = j + (i << 8);
            expanded_key[j] ^= blk_stuff1_p1[v10] ^ stack_stuff[v10];
        }
    }
    
    uint8_t scratch[16] = {};
    for (int i = 0; i < 16; i++) {
        uint8_t t = xor_combine(&expanded_key[16 * index_scramble[i]]);
        scratch[i] = blk_stuff1_p6[t] ^ ~t;
    }
    // yes, also usually xor'd
    memset(expanded_key, 0, sizeof(expanded_key));
    for (uint64_t i = 0; i < 16; i++)
        expanded_key[i * 16] = scratch[i];
    for (int i = 0; i < sizeof(expanded_key); i++)
        expanded_key[i] ^= blk_stuff1_p7[i] ^ stack_stuff[i + 0xA00];

    for (int i = 0; i < 16; i++)
        key[i] = xor_combine(&expanded_key[16 * i]);
}

int main() {
    //auto* blk_file = fopen("D:\\genshinimpactre\\1.5-dev\\YuanShen_Data\\StreamingAssets\\20527480.blk", "rb");
    auto* blk_file = fopen("D:\\Games\\Genshin Impact\\Genshin Impact game\\GenshinImpact_Data\\StreamingAssets\\VideoAssets\\26236578.blk", "rb");
    if (!blk_file) {
        printf("failed to open blk\n");
        return 1;
    }

    {
        uint32_t magic = 0;
        fread(&magic, 4, 1, blk_file);
        if (magic != 0x6B6C62) { // blk\x00
            printf("bad file magic");
            return 1;
        }
    }

    {
        uint32_t unk1 = 0;
        fread(&unk1, 4, 1, blk_file);
        if (unk1 != 0x10) {
            printf("unk1 is not 0x10");
            return 1;
        }
    }

    uint8_t key[16] = {};
    fread(key, sizeof(key), 1, blk_file);
    fseek(blk_file, 16, SEEK_CUR); // skip the useless half of the key
    hexdump("encrypted blk key:", key, sizeof(key));
	key_scramble1(key);
	key_scramble2(key);
    // this should also go into magic_constants.h, but it's small
    // this value goes through a lot of computation to get generated, but is always the same
    uint8_t hard_key[] = { 0xE3, 0xFC, 0x2D, 0x26, 0x9C, 0xC5, 0xA2, 0xEC, 0xD3, 0xF8, 0xC6, 0xD3, 0x77, 0xC2, 0x49, 0xB9 };
    for (int i = 0; i < 16; i++)
        key[i] ^= hard_key[i];
    hexdump("decrypted blk key:", key, sizeof(key));

    uint16_t size = 0;
    fread(&size, sizeof(size), 1, blk_file);

    auto* data = new uint8_t[size];
    fread(data, size, 1, blk_file);
    fclose(blk_file);

    /*
    uint8_t xorpad[4096] = {};
    create_decrypt_vector(key, data, size, xorpad, sizeof(xorpad));

    auto len = std::min((uint64_t)size, sizeof(xorpad));
    for (int i = 0; i < len; i++)
        data[i] ^= xorpad[i];
    */

    uint8_t xorpad[4096] = {};
    for (size_t processed = 0; processed < size; ) {
        size_t to_process = std::min((uint64_t)size, sizeof(xorpad));
        create_decrypt_vector(key, data + processed, to_process, xorpad, sizeof(xorpad));
        for (int i = 0; i < to_process; i++)
            data[i] ^= xorpad[i];
        processed += to_process;
    }

    auto* output = fopen("decrypted.bin", "wb");
    if (!output) {
        printf("failed to open output\n");
        return 1;
    }
    fwrite(data, size, 1, output);
    fclose(output);
}