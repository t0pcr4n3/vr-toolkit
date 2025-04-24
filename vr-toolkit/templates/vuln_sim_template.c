#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

struct dhcpv6_option {
    uint16_t option_code;
    uint16_t option_length;
    uint8_t payload[65535];
};

void relay_relay_reply(const uint8_t *msg, int32_t len) {
    static uint8_t buffer[4096];
    uint8_t *cur = buffer;
    const struct dhcpv6_option *opt = (struct dhcpv6_option *)msg;
    uint16_t len_to_copy = ntohs(opt->option_length);
    memcpy(cur, opt->payload, len_to_copy); // ☠️ Vulnerable
    printf("Copied %u bytes into 4096 buffer\n", len_to_copy);
}
