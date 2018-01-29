#ifndef HUST_UDP_HELPER_H
#define HUST_UDP_HELPER_H

#include <netinet/in.h>

int Socket();
int Bind(int fd, int port);
int Recvfrom(int fd, char *buf, int len, struct sockaddr *clientAddr, socklen_t *size);
int Close(int fd);

#endif