#include "timekey.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

bool generate_time_key(uint64_t time_slot, uint8_t* key_out, size_t key_len) {
    if (!key_out || key_len == 0) return false;
    
    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer), "%s:%llu", MASTER_SEED, 
                      (unsigned long long)time_slot);
    
    if (len <= 0 || len >= (int)sizeof(buffer)) return false;
    
    uint8_t hash[SHA256_BLOCK_SIZE];
    sha256((uint8_t*)buffer, len, hash);
    
    size_t copy_len = (key_len < SHA256_BLOCK_SIZE) ? key_len : SHA256_BLOCK_SIZE;
    memcpy(key_out, hash, copy_len);
    
    return true;
}

uint64_t get_current_time_slot() {
    time_t now = time(NULL);
    return (uint64_t)now / KEY_ROTATION_INTERVAL;
}

void encrypt_with_current_key(uint8_t* data, uint32_t length) {
    uint8_t key[32];
    uint64_t slot = get_current_time_slot();
    if (!generate_time_key(slot, key, sizeof(key))) return;
    for (uint32_t i = 0; i < length; i++) {
        data[i] ^= key[i % sizeof(key)];
    }
}

bool verify_with_time_windows(const uint8_t* data, uint32_t length, const uint8_t* encrypted) {
    if (!data || !encrypted || length == 0) return false;
    
    uint64_t current_slot = get_current_time_slot();
    uint8_t key[32];
    uint8_t* temp = (uint8_t*)malloc(length);
    if (!temp) return false;
    
    for (int offset = -1; offset <= 1; offset++) {
        uint64_t test_slot = current_slot + offset;
        
        if (!generate_time_key(test_slot, key, sizeof(key))) {
            continue;
        }
        
        memcpy(temp, encrypted, length);
        for (uint32_t i = 0; i < length; i++) {
            temp[i] ^= key[i % sizeof(key)];
        }
        
        if (memcmp(temp, data, length) == 0) {
            free(temp);
            return true;
        }
    }
    
    free(temp);
    return false;
}
