#ifndef C_HOOK_H
#define C_HOOK_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

#define ABI_VERSION 0x1

#define DNS_MAX_HOSTNAME_LEN 255
#define DNS_MAX_PACKET_SIZE 8192

typedef struct ParsedPacket ParsedPacket;
typedef struct SessionState SessionState;
typedef struct CErr CErr;

typedef struct EdgeDNSFnTable
{
    const char *(*error_description)(const CErr *err);
    int (*set_session_id)(SessionState *session_state, const CErr **err, const char *session_id, size_t session_id_len);
    int (*env_insert_str)(SessionState *session_state, const CErr **err,
                          const char *key, size_t key_len, const char *val, size_t val_len);
    int (*env_insert_i64)(SessionState *session_state, const CErr **err,
                          const char *key, size_t key_len, int64_t i64);
    int (*env_get_str)(const SessionState *session_state, const CErr **err,
                       const char *key, size_t key_len, char *val_p, size_t *val_len_p, size_t val_max_len);
    int (*env_get_i64)(const SessionState *session_state, const CErr **err,
                       const char *key, size_t key_len, int64_t *i64);
} EdgeDNSFnTable;

typedef struct FnTable
{
    const char *(*error_description)(const CErr *err);
    uint32_t (*flags)(const ParsedPacket *parsed_packet);
    void (*set_flags)(ParsedPacket *parsed_packet, uint32_t flags);
    uint8_t (*rcode)(const ParsedPacket *parsed_packet);
    void (*set_rcode)(ParsedPacket *parsed_packet, uint8_t rcode);
    uint8_t (*opcode)(const ParsedPacket *parsed_packet);
    void (*set_opcode)(ParsedPacket *parsed_packet, uint8_t opcode);
    void (*iter_answer)(ParsedPacket *parsed_packet, bool (*cb)(void *ctx, void *it), void *ctx);
    void (*iter_nameservers)(ParsedPacket *parsed_packet, bool (*cb)(void *ctx, void *it), void *ctx);
    void (*iter_additional)(ParsedPacket *parsed_packet, bool (*cb)(void *ctx, void *it), void *ctx);
    void (*iter_edns)(ParsedPacket *parsed_packet, bool (*cb)(void *ctx, void *it), void *ctx);
    void (*name)(void *it, char name[DNS_MAX_HOSTNAME_LEN + 1]);
    uint16_t (*rr_type)(void *it);
    uint16_t (*rr_class)(void *it);
    uint32_t (*rr_ttl)(void *it);
    void (*set_rr_ttl)(void *it, uint32_t ttl);
    void (*rr_ip)(void *it, uint8_t *addr, size_t *addr_len);
    void (*set_rr_ip)(void *it, const uint8_t *addr, size_t addr_len);
    int (*raw_name_from_str)(uint8_t raw_name[DNS_MAX_HOSTNAME_LEN + 1], size_t *raw_name_len, const CErr **err, const char *name, size_t name_len);
    int (*set_raw_name)(void *it, const CErr **err, const uint8_t *name, size_t name_len);
    int (*set_name)(void *it, const CErr **err, const char *name, size_t name_len, const uint8_t *default_zone_raw, size_t default_zone_raw_len);
    int (*delete_rr)(void *it, const CErr **err);
    int (*add_to_question)(ParsedPacket *parsed_packet, const CErr **err, const char *rr_str);
    int (*add_to_answer)(ParsedPacket *parsed_packet, const CErr **err, const char *rr_str);
    int (*add_to_nameservers)(ParsedPacket *parsed_packet, const CErr **err, const char *rr_str);
    int (*add_to_additional)(ParsedPacket *parsed_packet, const CErr **err, const char *rr_str);
    int (*raw_packet)(const ParsedPacket *parsed_packet, uint8_t raw_packet[DNS_MAX_PACKET_SIZE], size_t *raw_packet_len, size_t max_len);
    int (*question)(const ParsedPacket *parsed_packet, char name[DNS_MAX_HOSTNAME_LEN + 1], uint16_t *rr_type);
    uint64_t abi_version;
} FnTable;

typedef enum Action {
    ACTION_PASS = 1,
    ACTION_LOOKUP,
    ACTION_DROP
} Action;

Action hook_recv(const EdgeDNSFnTable *edgedns_fn_table, SessionState *session_state, const FnTable *fn_table, ParsedPacket *parsed_packet);
Action hook_deliver(const EdgeDNSFnTable *edgedns_fn_table, SessionState *session_state, const FnTable *fn_table, ParsedPacket *parsed_packet);

#endif
