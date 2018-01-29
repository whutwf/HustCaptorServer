#include "captask.h"
#include <string.h>

#include <sys/time.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "udp_helper.h"
#include "config.h"
#include "pcap.h"

typedef struct
{
    int cap_state;
    volatile int quit_cmd_loop;
    volatile int quit_cap_loop;
    int sFd;
    unsigned char recv_buffer[RECV_BUFFER_SIZE];
    char eth_name[32];
    pthread_t tidAction;
    pthread_t tidCap;
    pthread_mutex_t mutex;
    pthread_cond_t threshold_cap;

} p_CapStateInstance;

static p_CapStateInstance capStateInstance_p;

// pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/** send cmd result to client */
static void send_cmd_res(int fd , int cmd_type, char*cmd_buf, int cmd_buf_len, struct sockaddr * addr , socklen_t addrlen)
{
    char content[36];
    /*  the content byte
     *  type 4
     *  len 4
     *  ifname 16
     *  ip  4
     *  unused 4
     *  unused 4
     * */
    memset(content,0,36);
    memcpy(content,&cmd_type,4);
    if(cmd_buf_len>0)
    {
        memcpy(content+4, &cmd_buf_len, cmd_buf_len);
        memcpy(content+8, cmd_buf, cmd_buf_len);
    }
    if (sendto(fd, content, 36, 0, addr, addrlen ) == -1) {
        perror("[Send Cmd Res] send cmd res error");
    }
}

static int write_ether_interfaces(int fd, struct sockaddr *clientAddr, socklen_t size)
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs == NULL)
    {
        perror("[if_nameindex] Error: get ethernet interfaces");
        send_cmd_res(fd, GetIf_End, NULL, 0, clientAddr, size);
        return -1;
    }

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0) {
        perror("[if_nameindex] Error: get socket when to get ethernet interfaces");
        send_cmd_res(fd, GetIf_End, NULL, 0, clientAddr, size);
        return -1;
    }
    for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
    {
        char contentbuf[20];
        struct ifreq ifr;

        strcpy(ifr.ifr_name, intf->if_name);
        ioctl(sockfd, SIOCGIFADDR, &ifr);

        memset(contentbuf, 0, 20);
        memcpy( contentbuf, intf->if_name, 16);
        memcpy(contentbuf+16, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, 4);

        send_cmd_res(fd, GetIf_Content, contentbuf, 20, clientAddr, size);

        // printf("[if_nameindex] %s %d  %s\n", intf->if_name, intf->if_index  ,inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    }

    send_cmd_res(fd, GetIf_End, NULL, 0, clientAddr, size);
    return 0;
}

static void ethernet_set_misc(int sockfd, struct ifreq *ethreq, const char *eth_name) {

    if (ioctl(sockfd, SIOCGIFFLAGS, &ethreq) < 0) {
        perror("Error: get interface flags\n");
    } else {
        ethreq->ifr_flags |=IFF_PROMISC;
    }

    if (ioctl(sockfd, SIOCSIFFLAGS, &ethreq) < 0) {
        perror("Error: set interface flags\n");
    }
}

static int ethernet_bind(const char *eth_name)
{
    struct ifreq ethreq;
    struct sockaddr_ll saddr_ll;

    capStateInstance_p.sFd = -1;
    capStateInstance_p.sFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (capStateInstance_p.sFd < 0) {
        perror("Error: receive data sock create\n");
        return -1;
    } else {
        bzero(&saddr_ll, sizeof(saddr_ll));
        memcpy(ethreq.ifr_name, eth_name, strlen(eth_name));
        ethernet_set_misc(capStateInstance_p.sFd, &ethreq, eth_name);
        if(ioctl(capStateInstance_p.sFd, SIOCGIFINDEX, &ethreq) < 0) {
            perror("Error: get interface index\n");
            close(capStateInstance_p.sFd);
            return -1;
        }

        saddr_ll.sll_family = PF_PACKET;
        saddr_ll.sll_ifindex = ethreq.ifr_ifindex;
        saddr_ll.sll_protocol = htons(ETH_P_ALL);

        capStateInstance_p.sFd = (bind(capStateInstance_p.sFd, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll)) < 0)
                                 ? -1
                                 : capStateInstance_p.sFd;

        return capStateInstance_p.sFd;
    }
}

static int ethernet_data_fetch()
{
    int err, signo;

    pthread_cond_wait(&capStateInstance_p.threshold_cap, &capStateInstance_p.mutex);
    if ((ethernet_bind(capStateInstance_p.eth_name)) < 0) {
        perror("Error:ethernet_bind\n");
        return -1;
    } else {
        int clientFd = -1;
        if ((clientFd = Socket()) == -1) {
            return -1;
        }

        struct sockaddr_in servaddr;

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(TARGET_PORT);
        inet_pton(AF_INET, TARGET_HOST, &servaddr.sin_addr);

        int recv_length = 0;

        while (!capStateInstance_p.quit_cap_loop) {
            if (capStateInstance_p.cap_state != StartCap_State) {
                pthread_cond_wait(&capStateInstance_p.threshold_cap, &capStateInstance_p.mutex);
            }
            recv_length = recvfrom(capStateInstance_p.sFd, capStateInstance_p.recv_buffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
            buf_print((char *)capStateInstance_p.recv_buffer, recv_length);
            if (sendto(clientFd, capStateInstance_p.recv_buffer,
                       recv_length, 0,
                       (struct sockaddr*)&servaddr,
                       sizeof(servaddr)) == -1) {
                perror("[Cap Task] send data failed");
            }
        }

        Close(capStateInstance_p.sFd);
        Close(clientFd);
    }

    return 0;
}

static void stop() {
    pthread_mutex_lock (&capStateInstance_p.mutex);
    capStateInstance_p.quit_cap_loop = 1;
    pthread_mutex_unlock (&capStateInstance_p.mutex);
}

static void do_action(void) {
    char cmd_buf[64];
    Com_Cmd_Info *comCmdInfo;
    fd_set rset;
    FD_ZERO(&rset);

    int serverFd = -1;
    serverFd = Socket();
    if (serverFd < 0) {
        memset(&capStateInstance_p, 0, sizeof(capStateInstance_p));
        return;
    }
    if (Bind(serverFd, LOCAL_PORT) == -1) {
        return;
    }

    struct sockaddr_in cliaddr;
    int addrlen = sizeof(cliaddr);

    while (!capStateInstance_p.quit_cmd_loop) {
        FD_SET(serverFd, &rset);
        select(serverFd + 1, &rset, NULL, NULL, NULL);

        if (FD_ISSET(serverFd, &rset)) {
            int len = Recvfrom(serverFd, cmd_buf, 64
                               , (struct sockaddr *)&cliaddr
                               , (socklen_t *)&addrlen);
            if(len > 0) {
                comCmdInfo = (Com_Cmd_Info *)cmd_buf;
            }
        } else {
            perror("[Cap Task] no select fd");
        }

        printf("[Cap Task] the cmd num %d\n", comCmdInfo->cmd);
        switch(comCmdInfo->cmd) {
        case GetIf_Cmd:
        {
            if (capStateInstance_p.cap_state == Init_State
                    || capStateInstance_p.cap_state == GetIf_State) {
                printf("[Cap Task] the cmd is get if\n");
                if (write_ether_interfaces(serverFd
                                           , (struct sockaddr *)&cliaddr
                                           , (socklen_t)addrlen) == -1 ) {
                    break;
                }
                capStateInstance_p.cap_state = GetIf_State;
            }
            break;
        }
        case SetIf_Cmd: {
            if (capStateInstance_p.cap_state == GetIf_State) {
                sprintf(capStateInstance_p.eth_name, "%s%d", comCmdInfo->buf, comCmdInfo->info);
                capStateInstance_p.cap_state = SetIf_State;

                printf("[Cap Task] the cmd is set if\n");
            }
            break;
        }
        case StartCap_Cmd:
        {
            if (capStateInstance_p.cap_state == SetIf_State
                    || capStateInstance_p.cap_state == StopCap_State) {
                printf("[Cap Task] the cmd is start if\n");

                pthread_cond_signal(&capStateInstance_p.threshold_cap);
                capStateInstance_p.cap_state = StartCap_State;
            }
            break;
        }
        case StopCap_Cmd:
        {
            if (capStateInstance_p.cap_state == StartCap_State) {
                printf("[Cap Task] the cmd is stop if\n");
                capStateInstance_p.cap_state = StopCap_State;
            }
            break;
        }
        case CapIsEmpty_Cmd:
        {
            if (capStateInstance_p.cap_state == StopCap_State) {
                printf("[Cap Task] the cmd is empty if\n");

                capStateInstance_p.cap_state = Init_State;
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }

    Close(serverFd);
}

void start() {
    memset(&capStateInstance_p, 0, sizeof(capStateInstance_p));
    capStateInstance_p.cap_state = No_State;
    capStateInstance_p.quit_cmd_loop = 0;
    capStateInstance_p.quit_cap_loop = 0;
    capStateInstance_p.cap_state = Init_State;
    /* Initialise mutex and condition variables */
    pthread_mutex_init(&capStateInstance_p.mutex, NULL);
    pthread_cond_init (&capStateInstance_p.threshold_cap, NULL);

    int err;
    err = pthread_create(&capStateInstance_p.tidAction, NULL, (void *)do_action, NULL);

    if (err != 0) {
        perror("[Cap Task] create do action thread failed");
    }

    err = pthread_create(&capStateInstance_p.tidCap, NULL, (void *)ethernet_data_fetch, NULL);

    if (err != 0) {
        perror("[Cap Task] create cap thread failed");
    }

    pthread_join (capStateInstance_p.tidAction, NULL);
    pthread_join (capStateInstance_p.tidCap, NULL);
    while(1);
}