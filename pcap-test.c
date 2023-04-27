#include <netinet/in.h>
#include <stdbool.h>
#include <memory.h>
#include <stdio.h>
#include <pcap.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

typedef union {
    uint8_t bytes[14];
    struct __attribute__((packed)) {
        uint8_t destMacAddr[6];
        uint8_t srcMacAddr[6];
        uint8_t etherType[2];
    } fields;
} MacHeader, * pMacHeader;

typedef union {
    uint8_t bytes[20];
    struct __attribute__((packed)) {
        uint8_t  version4_ihl4;
        uint8_t  dscp6_ecn2;
        uint16_t totalLength;
        uint16_t identification;
        uint16_t flags3_fragmentOffset13;
        uint8_t  timeToLive;
        uint8_t  protocol;
        uint16_t headerChecksum;
        uint32_t srcIpAddr;
        uint32_t destIpAddr;
    } fields;
} IPheader, * pIPheader;

typedef union {
    uint8_t bytes[20];
    struct __attribute__((packed)) {
        uint16_t srcPort;
        uint16_t destPort;
        uint32_t sequenceNumber;
        uint32_t AcknowledgmentNumber;
        uint16_t flags;
        uint16_t windowSize;
        uint16_t checksum;
        uint16_t urgentPointer;
    } fields;
} TCPheader, * pTCPheader;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
	    fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
	    return -1;
    }

    while (true) {
        const u_char * packet   = NULL,
                     * baseAddr = NULL;

        struct pcap_pkthdr * header = NULL;
        int                res      = pcap_next_ex(pcap, &header, &packet);

        MacHeader macHdr = (MacHeader) { };
        IPheader  ipHdr  = (IPheader)  { };
        TCPheader tcpHdr = (TCPheader) { };
        
        memmove(macHdr.bytes, baseAddr =  packet,                                   sizeof macHdr); 
        memmove(ipHdr.bytes,  baseAddr += sizeof macHdr,                            sizeof ipHdr);
        memmove(tcpHdr.bytes, baseAddr += (ipHdr.fields.version4_ihl4 & 0x0F) << 2, sizeof tcpHdr);

        baseAddr += (tcpHdr.fields.flags >> 4 & 0x000F) << 2;
        
        if (res == 0) continue;
	    
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
	    
        printf("%u bytes captured\n", header->caplen);
	    
        if (*(uint16_t *)macHdr.fields.etherType == 8 && ipHdr.fields.protocol == 6) {
            uint32_t payload_length = header->len - (baseAddr - packet);
            
            payload_length = payload_length > 10 ? 10 : payload_length;
            
            printf("[TCP Packet]\n");
            printf("Ethernet Header - src mac   : 0x%04X%08X\n", ntohs(*(uint16_t *)macHdr.fields.srcMacAddr),  ntohl(*(uint32_t *)(macHdr.fields.srcMacAddr + 2)));
            printf("Ethernet Header - dest mac  : 0x%04X%08X\n", ntohs(*(uint16_t *)macHdr.fields.destMacAddr), ntohl(*(uint32_t *)(macHdr.fields.destMacAddr + 2)));
            printf("IP Header       - src ip    : 0x%08X\n",     ntohl(ipHdr.fields.srcIpAddr));
            printf("IP Header       - dest ip   : 0x%08X\n",     ntohl(ipHdr.fields.destIpAddr));
            printf("TCP Header      - src port  : 0x%04X\n",     ntohs(tcpHdr.fields.srcPort));
            printf("TCP Header      - dest port : 0x%04X\n",     ntohs(tcpHdr.fields.destPort));
            printf("Payload                     : \n");

            for (uint32_t i = 0; i < payload_length; i++) {
                printf("%02X ", baseAddr[i]);
                
                if (!((i + 1) % 16)) puts("");
            }
            
            if (payload_length % 16) puts("");
            
            puts("");
        }
    }

    pcap_close(pcap);
}
