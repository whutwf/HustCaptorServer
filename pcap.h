#ifndef __PCAP_H__
#define __PCAP_H__

/*
typedef signed char u_char8_t;
typedef signed short u_int16_t;
typedef signed int u_int32_t;
typedef signed long long u_int64_t;
typedef unsigned char u_uchar8_t;
typedef unsigned short u_uint16_t;
typedef unsigned int u_uint32_t;
typedef unsigned long long u_uint64_t;
typedef unsigned long u_word_t;*/

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <stdint.h>

#define TCPDUMP_MAGIC       0xa1b2c3d4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE	    1
#define PCAP_SNAPLEN	    0x0000ffff	//逆序记载0xffff0000
#define MMAP_PAGE_SIZE	    65535
#define RECV_BUFFER_SIZE    2048

/**32进制IP转化，可以用 char* inet_ntoa(struct in_addr addr) */
#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

/**---------pcap file struct using--------- */
struct pcap_file_hdr {
    unsigned int magic;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;	/* gmt to local correction */
    unsigned int sigfigs;	/* accuracy of timestamps */
    unsigned int snaplen;	/* max length saved portion of each pkt */
    unsigned int linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_packet_hdr {
    unsigned int tv_sec;        /* Seconds. */
    unsigned int tv_usec;  /* Microseconds. */
    unsigned int caplen;		/* length of portion present */
    unsigned int len;		/* length this packet (off wire) */
};

/**---------net struct using--------- */
#define ETH_ALEN    6
struct ethernet_hdr {
    unsigned char eth_dst[ETH_ALEN];
    unsigned char eth_src[ETH_ALEN];
    unsigned short eth_proto;
};
struct ipv4_hdr {
    uint8_t ip_hl : 4;     /* header length */
    uint8_t ip_v : 4;      /* version */
    uint8_t ip_tos;            /* type of service */
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;           /* fragment offset field */
    uint8_t ip_ttl;            /* time to live */
    uint8_t ip_proto;
    uint16_t ip_checksum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t len;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

struct tcp_info {};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

struct udp_info {};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

unsigned int pcap_file_create(const char *pcap_file_name);

unsigned int pcap_write_file_hdr(unsigned int fd);

unsigned int pcap_write_packet_hdr(unsigned int fd, unsigned int data_len);

unsigned int pcap_write_packet_data(unsigned int fd, const unsigned char *data, unsigned int data_len);

inline void pcap_file_close(unsigned int fd)
{
    close(fd);
}

int pcap_parser(const unsigned char *data);
void pcap_file_hdr_print(struct pcap_file_hdr *pf_hdr);
void buf_print(const char *buf, int n);

#ifdef __cplusplus
}
#endif
#endif