#include "udp_helper.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

enum Dispay {
    TRUE = 0,
    FALSE
};

typedef struct {
    struct sockaddr_in serverAddr;  //服务器套接字
    int sockAddrSize;       //套接字地址数据结构大小
    enum Dispay display;     //如果为True
    int mLen;      //信息长度
} u_UdpSocketInstance;

int Socket() {

    int fd = -1;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("[Udp Socket] socket create error");
        return -1;
    }

    return fd;
}

int Bind(int fd, int port) {
    u_UdpSocketInstance serverInsace_u;
    memset(&serverInsace_u, 0, sizeof(serverInsace_u));

    serverInsace_u.sockAddrSize = sizeof(struct sockaddr_in);
    bzero((char *) &serverInsace_u.serverAddr, serverInsace_u.sockAddrSize);
    serverInsace_u.serverAddr.sin_family = AF_INET;
    serverInsace_u.serverAddr.sin_port = htons(port);
    serverInsace_u.serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((bind(fd
              , (struct sockaddr *) &serverInsace_u.serverAddr
              , serverInsace_u.sockAddrSize)) == -1) {
        perror("[Udp Socket] bind fail");
        return -1;
    }

    return 0;

}

int Recvfrom(int fd, char *buf, int len, struct sockaddr *clientAddr, socklen_t *size) {
    int rlen;
    if ((rlen = recvfrom(
                    fd
                    , buf
                    , len
                    , 0
                    , clientAddr
                    , size)) == -1) {
        perror("[Udp Receive] receive data error");
        return -1;
    }
    return len;
}

int Close(int fd) {
    if (close (fd) == -1) {
        perror("[Udp Close] close socket error");
        return -1;
    }

    return 0;
}