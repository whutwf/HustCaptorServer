#include "pcap.h"
#include "config.h"
#include <arpa/inet.h>

unsigned int
pcap_file_create(const char *pcap_file_name)
{
    unsigned int fd = open(pcap_file_name, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "can't open %s\n", pcap_file_name);
    }

    return fd;
}

unsigned int
pcap_write_file_hdr(unsigned int fd)
{
    if (fd == -1) {
        return -1;
    }
    unsigned int file_header_size = sizeof(struct pcap_file_hdr);
    struct pcap_file_hdr head;
    head.magic = TCPDUMP_MAGIC;
    head.version_major = PCAP_VERSION_MAJOR;
    head.version_minor = PCAP_VERSION_MINOR;
    head.thiszone = 0;
    head.sigfigs = 0;
    head.snaplen = PCAP_SNAPLEN;
    head.linktype = PCAP_LINKTYPE;

    if (write(fd, &head, file_header_size) !=file_header_size) {
        perror("Error: write file header\n");
        return -1;
    }

    return 0;
}

unsigned int
pcap_write_packet_hdr(unsigned int fd, unsigned int data_len)
{
    unsigned int phead_size = sizeof(struct pcap_packet_hdr);
    struct pcap_packet_hdr phead;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    phead.tv_sec = tv.tv_sec;
    phead.tv_usec = tv.tv_usec;
    phead.caplen = data_len;
    phead.len = phead.caplen;

    if (write(fd, &phead, phead_size) != phead_size) {
        perror("Error: write pacaket header\n");
        return -1;
    }

    return 0;
}

unsigned int
pcap_write_packet_data(unsigned int fd, const unsigned char *data, unsigned int data_len)
{
    if (write(fd, data, data_len) != data_len) {
        perror("Error: write pacaket data\n");
        return -1;
    }
    return 0;
}

int pcap_parser(const unsigned char *data)
{
    if (data == NULL) {
        perror("[PCAP] Error: data to parse is null\n");
        return -1;
    }
    struct ethernet_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct tcp_hdr *tcp_hdr;
    struct udp_hdr *udp_hdr;
    struct icmp_hdr *icmp_hdr;

    eth_hdr = (struct ethernet_hdr *)data;
    eth_hdr->eth_proto = ntohs(eth_hdr->eth_proto);
    switch (eth_hdr->eth_proto) {
    case 0x0800:
        ip_hdr = (struct ipv4_hdr *)(data + sizeof(struct ethernet_hdr));
        if (ip_hdr->ip_proto == IPPROTO_TCP) {
            tcp_hdr = (struct tcp_hdr *)(data + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr));
            fprintf(stdout, "%d.%d.%d.%d\t%d.%d.%d.%d\t%d\t",
                    NIPQUAD(ip_hdr->ip_dst), NIPQUAD(ip_hdr->ip_src), ntohs(ip_hdr->ip_len));
            fprintf(stdout, "%u\t%u\t%d\t\n",
                    ntohl(tcp_hdr->seq_num), ntohl(tcp_hdr->ack_num),ntohs(tcp_hdr->window));
        } else if (ip_hdr->ip_proto == IPPROTO_UDP) {
            udp_hdr = (struct udp_hdr *)(data + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr));
        } else if (ip_hdr->ip_proto == IPPROTO_ICMP) {
            icmp_hdr = (struct icmp_hdr *)(data + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr));
        }
        break;
    case 0x0806:
        break;
    default:
        break;
    }
    return 0;
}

void
pcap_file_hdr_print(struct pcap_file_hdr *pf_hdr)
{
    fprintf (stdout, "magic number = %x\n", pf_hdr->magic);
    fprintf (stdout, "version_major = %u\n", pf_hdr->version_major);
    fprintf (stdout, "version_minor = %u\n", pf_hdr->version_minor);
    fprintf (stdout, "thiszone = %d\n", pf_hdr->thiszone);
    fprintf (stdout, "sigfigs = %u\n", pf_hdr->sigfigs);
    fprintf (stdout, "snaplen = %u\n", pf_hdr->snaplen);
    fprintf (stdout, "linktype = %u\n", pf_hdr->linktype);
}

void
buf_print(const char *buf, int n) {
    int i;
    for(i=0; i<n; i++) {
        if( i % 16 == 0) printf("\n%04d: ", i);
        else if(i % 8 == 0) printf(" ");
        fprintf(stdout, "%02x ", buf[i] & 0xff);
    }
    fprintf(stdout, " %04d\n", n);
}