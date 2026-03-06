/*
 * test_validation_patterns.c - Test code with validation patterns
 *
 * This file demonstrates various validation patterns that should
 * elevate taint from RAW to SYNTACTIC or SEMANTIC.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mock structures (mosquitto-like)
struct packet
{
    uint8_t *payload;
    uint32_t pos;
    uint32_t remaining_length;
};

#define SUCCESS 0
#define ERR_MALFORMED 1
#define ERR_NOMEM 2

// ============================================================
// Forward declarations (would be in headers)
// ============================================================

void process_message_id (uint16_t mid);
void handle_qos (uint8_t qos);
void handle_publish (void);
void handle_subscribe (void);
int read_string (struct packet *pkt, char **str, uint16_t *len);
void register_client (const char *id, uint16_t len, uint16_t keepalive);
void process_byte (uint8_t b);

// ============================================================
// Pattern 1: Error-checked parser call
// ============================================================
// After: rc is SYNTACTIC (checked)
// After: value is SYNTACTIC (from parser with error check)

int read_uint16 (struct packet *pkt, uint16_t *value);

void
test_error_checked_parser (struct packet *pkt)
{
    uint16_t mid;
    int rc;

    // Parser call with error check
    rc = read_uint16 (pkt, &mid);
    if (rc)
        {
            return; // Error path
        }

    // Here: mid should be SYNTACTIC
    // Because read_uint16 parsed it and we checked for errors

    process_message_id (mid); // Safe to use
}

// ============================================================
// Pattern 2: Bounds checking
// ============================================================
// After check: qos is SEMANTIC (range validated)

void
test_bounds_check (uint8_t header)
{
    // Extract QoS from header
    uint8_t qos = (header & 0x06) >> 1; // Can only be 0-3

    // Bounds check
    if (qos > 2)
        {
            return; // Invalid QoS
        }

    // Here: qos is SEMANTIC
    // We know: 0 <= qos <= 2

    handle_qos (qos); // Safe
}

// ============================================================
// Pattern 3: Equality check against enum
// ============================================================

#define TYPE_CONNECT 1
#define TYPE_PUBLISH 2
#define TYPE_SUBSCRIBE 3

void
test_equality_check (int msg_type)
{
    // msg_type is RAW (came from network)

    if (msg_type == TYPE_PUBLISH)
        {
            // Here: msg_type is SEMANTIC (we know exact value)
            handle_publish ();
        }
    else if (msg_type == TYPE_SUBSCRIBE)
        {
            // Here: msg_type is SEMANTIC
            handle_subscribe ();
        }

    // Outside: msg_type is still RAW
}

// ============================================================
// Pattern 4: Non-null check
// ============================================================

void
test_nonnull_check (char *topic)
{
    // topic is RAW pointer

    if (topic == NULL)
        {
            return;
        }

    // Here: topic is non-null (safe to deref)
    // Content is still RAW

    int len = strlen (topic); // Safe to call

    // But: topic[i] content is still RAW
}

// ============================================================
// Pattern 5: Combined validation (real-world example)
// ============================================================

int
handle_connect (struct packet *pkt)
{
    uint16_t keep_alive;
    char *client_id = NULL;
    uint16_t client_id_len;
    int rc;

    // Read keep-alive (error-checked parser)
    rc = read_uint16 (pkt, &keep_alive);
    if (rc)
        {
            return rc;
        }
    // keep_alive is SYNTACTIC

    // Read client ID
    rc = read_string (pkt, &client_id, &client_id_len);
    if (rc)
        {
            return rc;
        }
    // client_id is SYNTACTIC (parsed + error checked)

    // Additional validation
    if (client_id == NULL)
        {
            return ERR_MALFORMED;
        }
    // client_id is non-null

    if (client_id_len > 256)
        {
            free (client_id);
            return ERR_MALFORMED;
        }
    // client_id_len is SEMANTIC (range validated)

    // Now safe to use
    register_client (client_id, client_id_len, keep_alive);

    return SUCCESS;
}

// ============================================================
// Pattern 6: Bitmask extraction with implicit bounds
// ============================================================

void
test_bitmask_extraction (uint8_t command)
{
    // Extract fields from command byte
    uint8_t type = (command & 0xF0) >> 4; // 4 bits -> 0-15
    uint8_t dup = (command & 0x08) >> 3;  // 1 bit -> 0-1
    uint8_t qos = (command & 0x06) >> 1;  // 2 bits -> 0-3
    uint8_t retain = (command & 0x01);    // 1 bit -> 0-1

    // All these have implicit bounds from the bitmask
    // type:   0-15 (SEMANTIC - 4-bit value)
    // dup:    0-1  (SEMANTIC - boolean)
    // qos:    0-3  (SEMANTIC - 2-bit value)
    // retain: 0-1  (SEMANTIC - boolean)

    // But we might still want explicit validation for protocol
    if (qos > 2)
        {
            return; // QoS 3 is reserved
        }
    // qos: now known to be 0, 1, or 2
}

// ============================================================
// Pattern 7: Loop with array bounds
// ============================================================

void
test_array_bounds (uint8_t *data, uint32_t data_len)
{
    // data_len is RAW

    if (data_len > 1024)
        {
            return; // Too large
        }
    // data_len is SEMANTIC (bounded)

    for (uint32_t i = 0; i < data_len; i++)
        {
            // i is SEMANTIC (bounded by data_len which is bounded)
            process_byte (data[i]); // Safe array access
        }
}
