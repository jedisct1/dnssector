#ifndef C_HOOK_H
#define C_HOOK_H

#define ABI_VERSION 0x1

typedef struct ParsedPacket ParsedPacket;

typedef struct FnTable {
    uint64_t abi_version;
    uint32_t (*flags)(const ParsedPacket *parsed_packet);
    void     (*set_flags)(ParsedPacket *parsed_packet, uint32_t flags);
    uint8_t  (*rcode)(const ParsedPacket *parsed_packet);
    void     (*set_rcode)(ParsedPacket *parsed_packet, uint8_t rcode);
    uint8_t  (*opcode)(const ParsedPacket *parsed_packet);
    void     (*set_opcode)(ParsedPacket *parsed_packet, uint8_t opcode);
} FnTable;   

void hook(const FnTable *fn_table, ParsedPacket *parsed_packet);

#endif
