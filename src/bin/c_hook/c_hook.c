#include <assert.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "c_hook.h"

void hook(const FnTable *fn_table, ParsedPacket *parsed_packet)
{
    uint32_t flags;
    
    assert(fn_table->abi_version == ABI_VERSION);
    flags = fn_table->flags(parsed_packet);
    printf("flags as seen by the C hook: %" PRIx32 "\n", flags);
    fn_table->set_flags(parsed_packet, flags | 0x10);
}
