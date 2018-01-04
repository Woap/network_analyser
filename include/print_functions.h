#ifndef PRINT_FUNCTIONS_H
#define PRINT_FUNCTIONS_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>


#include <netinet/in.h>
#include <net/ethernet.h> // ethernet OK

#include <netinet/ip.h> // ip
#include <netinet/udp.h> // UDP
#include <netinet/tcp.h> // TCP
#include <net/if_arp.h> // OK

void print_ftp(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
void print_ethernetheader(const struct ether_header *ethernet);
void print_ipheader(const struct iphdr *ip);
void print_tcpheader(const struct tcphdr *tcp,int tcp_len);
void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet);
void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet);
void print_udpheader(const struct udphdr *udp);


#endif
