#ifndef TIMEKEY_H
#define TIMEKEY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define KEY_ROTATION_INTERVAL 600

#define KEY_WINDOW_SLOTS 3

#ifndef MASTER_SEED
#define MASTER_SEED "Random_Key" // Change here
#endif

/**
 * @param time_slot
 * @param key_out
 * @param key_len
 * @return
 */
bool generate_time_key(uint64_t time_slot, uint8_t* key_out, size_t key_len);

/**
 * @return
 */
uint64_t get_current_time_slot();

/**
 * @param data
 * @param length
 * @param encrypted
 * @return
 */
bool verify_with_time_windows(const uint8_t* data, uint32_t length, const uint8_t* encrypted);

/**
 * @param data 
 * @param length
 */
void encrypt_with_current_key(uint8_t* data, uint32_t length);

#endif // TIMEKEY_H
