#include <assert.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "c_hook.h"

static bool rr_it(void *ctx, void *it)
{
    const CErr *err;
    char name[DNS_MAX_HOSTNAME_LEN + 1];
    uint8_t default_zone[DNS_MAX_HOSTNAME_LEN + 1];
    size_t default_zone_len;
    int ret;

    FnTable *fn_table = ctx;
    fn_table->name(it, name);
    printf("- found RR [%s] with type: %" PRIu16 " and ttl: %" PRIu32 "\n",
           name, fn_table->rr_type(it), fn_table->rr_ttl(it));
    if (fn_table->rr_type(it) == 1)
    {
        uint8_t ip[4];
        size_t len = sizeof ip;
        fn_table->rr_ip(it, ip, &len);
        assert(len == 4);
        printf("\tip=%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    }
    else if (fn_table->rr_type(it) == 28)
    {
        uint32_t ip[4];
        size_t len = sizeof ip;
        fn_table->rr_ip(it, (uint8_t *)ip, &len);
        assert(len == 16);
        printf("\tip6=%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    }
    fn_table->set_rr_ttl(it, 42);
    fn_table->set_raw_name(it, NULL, (const uint8_t *)"\x02x2\x03net",
                           sizeof "\x02x2\x03net");
    fn_table->set_raw_name(it, NULL, (const uint8_t *)"\x01x\x03org",
                           sizeof "\x01x\x03org");
    fn_table->set_name(it, NULL, "example.com.", sizeof "example.com." - 1, NULL, 0);
    fn_table->set_name(it, NULL, "example.com", sizeof "example.com" - 1, NULL, 0);
    fn_table->raw_name_from_str(default_zone, &default_zone_len, NULL, "example.com", sizeof "example.com" - 1);
    fn_table->set_name(it, NULL, "www.prod", sizeof "www.prod" - 1, default_zone, default_zone_len);
    ret = fn_table->delete_rr(it, &err);
    assert(ret == 0);
    ret = fn_table->delete_rr(it, &err);
    assert(ret == -1);
    assert(strcmp(fn_table->error_description(err), "VoidRecord") == 0);

    return 0;
}

void hook(const FnTable *fn_table, ParsedPacket *parsed_packet)
{
    uint32_t flags;

    assert(fn_table->abi_version == ABI_VERSION);
    flags = fn_table->flags(parsed_packet);
    printf("flags as seen by the C hook: %" PRIx32 "\n", flags);
    fn_table->set_flags(parsed_packet, flags | 0x10);
    puts("Answer section");
    fn_table->iter_answer(parsed_packet, rr_it, fn_table);
    puts("Nameservers section");
    fn_table->iter_nameservers(parsed_packet, rr_it, fn_table);
    puts("Additional section");
    fn_table->iter_additional(parsed_packet, rr_it, fn_table);

    puts("Answer section");
    fn_table->iter_answer(parsed_packet, rr_it, fn_table);
    puts("Nameservers section");
    fn_table->iter_nameservers(parsed_packet, rr_it, fn_table);
    puts("Additional section");
    fn_table->iter_additional(parsed_packet, rr_it, fn_table);

    puts("Adding an extra record to the answer section");
    fn_table->add_to_answer(parsed_packet, NULL, "localhost.example.com. 3599 IN A 127.0.0.1");
    puts("Adding another extra record to the answer section");
    fn_table->add_to_answer(parsed_packet, NULL, "localhost.example.net. 4201 IN A 127.0.0.2");

    puts("New answer section");
    fn_table->iter_answer(parsed_packet, rr_it, fn_table);
}
