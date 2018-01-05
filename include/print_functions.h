/*
 * \file print_functions.h
 * \author IBIS Ibrahim
 *
 * Les fonctions permettant d'analyser et afficher le contenu des différents protocoles.
 * Protocole affichable : Ethernet, IP, TCP, UDP, HTTP, TELNET, ARP, BOOTP/DHCP, FTP, IMAP, SMTP, POP
 *
 */

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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include "bootp.h"
#include "dns.h"
#include "arp.h"

typedef enum { FTP, HTTP, IMAP, SMTP, POP} protocol_app;

int paquet_count;
struct in_addr paquet_srcaddr;
struct in_addr paquet_dstaddr;
int paquet_length;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518


void print_tcpoptions(const struct tcphdr *tcp, int size_ip,const u_char * packet,int verbosite,int count);
void print_dns(const u_char *payload, int len,int verbosite,int count);
void print_bootp(const u_char *payload, int len,int verbosite,int count);
void print_telnet(const u_char *payload, int len,int verbosite,int count);
void print_ftp_http_imap_smtp_pop(const u_char *payload, int len,protocol_app p,int verbosite,int count);
void print_ethernetheader(const struct ether_header *ethernet,int verbosite,int count);
void print_ipheader(const struct iphdr *ip,int verbosite,int count);
void print_tcpheader(const struct tcphdr *tcp,int tcp_len,int verbosite,int count);
void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet,int verbosite,int count);
void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet,int verbosite,int count);
void print_udpheader(const struct udphdr *udp,int verbosite,int count);
void print_arpheader(const struct my_arphdr *arp,const struct ether_header *ethernet,int verbosite,int count);



#endif
