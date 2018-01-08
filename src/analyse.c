/*
 * \file analyse.c
 * \author IBIS Ibrahim
 *
 * Analyseur réseau utilisant la librairie pcap
 * Protocole affichable : Ethernet, IP, TCP, UDP, HTTP, TELNET, ARP, BOOTP/DHCP, FTP, IMAP, SMTP, POP
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "../include/print_functions.h"

/* verbosite */
int verbosite = 0;


/* Traite un paquet en determinant les différents protocoles et appelle les fonctions d'affichage */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

        static int count = 0; // Numerotation paquets

        // Structures header
        const struct ether_header *ethernet;
        const struct iphdr *ip;
        const struct tcphdr *tcp;
        const struct udphdr *udp;
        const struct my_arphdr *arp;

        // Tailles
        int size_ip;
        int size_tcp;
        int size_payload;

        ethernet = (struct ether_header*)(packet);
        ip = (struct iphdr*)(packet + sizeof(struct ether_header));

        count++;


        printf("\n-------------------------------------\n");

        switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_IP: // IP
                paquet_srcaddr.s_addr = ip->saddr;
                paquet_dstaddr.s_addr = ip->daddr;
                paquet_count=count;
                paquet_length = __builtin_bswap16(ip->tot_len) + sizeof(struct ether_header);

                if ( verbosite >= 2 )
                {
                        printf("# Packet number %d - ", paquet_count);
                        printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                        printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                        printf("- Length : %d  \n\n",paquet_length);
                }

                if ( verbosite >= 2 )
                {
                        printf(" Ethernet II, ");
                        printf("Src: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                        printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                }
                if ( verbosite == 3 ) print_ethernetheader(ethernet,verbosite,count);  // Affichage header ethernet

                size_ip = ip->ihl*4;

                if ( verbosite == 3 ) printf("   ╚═ Type : IPv4 (%#06x) \n", ntohs(ethernet->ether_type));
                if ( verbosite >= 2 ) printf("\n   Internet Protocol Version 4, ");

                print_ipheader(ip,verbosite,count);

                switch(ip->protocol ) {
                case IPPROTO_TCP: // TCP

                        if ( verbosite == 3 ) printf("      ╚═ Protocol: TCP (%d)\n",ip->protocol);
                        tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
                        size_tcp = tcp->th_off*4;
                        int tcp_len = __builtin_bswap16(ip->tot_len)-size_ip-size_tcp;

                        if ( verbosite >= 2 ) printf("\n      Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d \n",ntohs(tcp->th_sport),ntohs(tcp->th_dport),(u_int)tcp->th_seq,ntohl(tcp->th_ack),tcp_len);
                        if ( verbosite == 3 ) print_tcpheader(tcp,tcp_len,verbosite,count);  // Affichage header tcp
                        if ( verbosite == 3 ) print_tcpoptions(tcp,size_ip,packet,verbosite,count);  // Affichage options tcp si existant

                        print_tcppayload(tcp,tcp_len,size_ip,ntohs(ip->tot_len),packet,verbosite,count); // Affichage du contenu tcp

                        return;
                case IPPROTO_UDP: // UDP

                        udp = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);
                        if ( verbosite == 3 ) printf("      ╚═ Protocol: UDP (%d)\n",ip->protocol);
                        if ( verbosite >= 2 ) printf("\n      User Datagram Protocol, Src Port: %d, Dst Port: %d \n",ntohs(udp->uh_sport),ntohs(udp->uh_dport));
                        if ( verbosite == 3 ) print_udpheader(udp,verbosite,count);  // Affichage header udp
                        print_udppayload(udp,size_ip,ntohs(ip->tot_len),packet,verbosite,count); // Affichage du contenu udp
                        return;
                case IPPROTO_ICMP: // ICMP

                        if ( verbosite == 3 ) printf("      ╚═ Protocol: ICMP (%d)\n",ip->protocol);
                        return;
                case IPPROTO_IP: // IP

                        if ( verbosite == 3 ) printf("      ╚═ Protocol: IP (%d)\n",ip->protocol);
                        return;
                default:

                        if ( verbosite == 3 ) printf("      ╚═ Protocol: unknown\n");
                        return;
                }
                break;

        case ETHERTYPE_ARP: // ARP

                paquet_srcaddr.s_addr = ip->saddr;
                paquet_dstaddr.s_addr = ip->daddr;
                paquet_count=count;
                size_payload = 60 - (sizeof(struct ether_header) + sizeof(struct my_arphdr));
                paquet_length = sizeof(struct my_arphdr) + sizeof(struct ether_header)+size_payload;

                if ( verbosite >= 2 )
                {
                        printf("# Packet number %d - ", paquet_count);
                        printf("Source: %02x:%02x:%02x:%02x:%02x:%02x - ", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                        printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                        printf("- Protocol : ARP - Length : %d  \n\n",paquet_length);
                }

                if ( verbosite >= 2 )
                {
                        printf(" Ethernet II, ");
                        printf("Src: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                        printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                }
                if ( verbosite == 3 ) print_ethernetheader(ethernet,verbosite,count);  // Affichage header ethernet
                if ( verbosite == 3 ) printf("   ╠═ Type : ARP (%#06x) \n", ntohs(ethernet->ether_type));

                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   ╚═ Padding (%d bytes) \n", size_payload);
                }

                if ( verbosite >= 2 ) printf("\n   Address Resolution Protocol \n");
                arp = (struct my_arphdr*)(packet + sizeof(struct ether_header));

                print_arpheader(arp,ethernet,verbosite,count); // Affichage arp ethernet

                break;
        case ETHERTYPE_REVARP: // RARP
                if ( verbosite == 3 ) printf("   Type : RARP (%#06x) \n", ntohs(ethernet->ether_type));
                break;
        default:
                if ( verbosite == 3 ) printf("   Type: unknown \n");

                break;
        }

}

void usage(char *prog)
{
        fprintf(stderr, "usage: %s ( -i <interface> | -o <fichier> ) [ -f <filtre> ] -v <1..3> \n\t  -i <interface> : interface pour l'analyse live \n\t  -o <fichier> : fichier d'entrée pour l'analyse offline\n\t  * choisir l'un ou l'autre \n\t  [ -f <filtre> ] : filtre BPF (optionnel) \n\t  -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet) \n", prog);
}

int main(int argc, char **argv)
{

        // ARGUMENTS
        char * progname = argv[0];
        extern char * optarg;
        int c;

        // Gestion arguments
        int iflag=0,oflag=0,fflag=0,vflag=0,errflag=0;
        char interface[1024];
        char fichier[1024];
        char filtre[1024];

        int nb = 0;

        while ((c = getopt(argc, argv, "i:o:f:v:")) != -1)
                switch (c) {
                case 'i':
                        iflag++;
                        strcpy(interface,optarg);
                        nb+=2;
                        break;
                case 'o':
                        oflag++;
                        strcpy(fichier,optarg);
                        nb+=2;
                        break;
                case 'f':
                        fflag++;
                        strcpy(filtre,optarg);
                        nb+=2;
                        break;
                case 'v':
                        vflag++;
                        verbosite=atoi(optarg);
                        nb+=2;
                        break;

                case '?':
                        errflag++;
                        break;
                }

        if (errflag || iflag == oflag || argc != nb+1 || vflag == 0)
        {
                usage(progname);
                return -1;
        }

        printf("Verbosité : %d \n",verbosite);

        // Variables Pcap
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        struct bpf_program fp;
        bpf_u_int32 net=0;



        if ( fflag == 1)
                printf("Filter expression: %s\n", filtre);

        // Online
        // Configuration pcap
        if ( iflag == 1 )
        {
                printf("Live capture \n");
                printf("Interface: %s\n", interface);

                handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
                if (handle == NULL) {
                        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
                        exit(EXIT_FAILURE);
                }

                if (pcap_datalink(handle) != DLT_EN10MB) {
                        fprintf(stderr, "%s is not an Ethernet\n", interface);
                        exit(EXIT_FAILURE);
                }

                if ( fflag == 1 )
                {
                        if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
                                fprintf(stderr, "Error filter ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }
                else {
                        if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
                                fprintf(stderr, "Error filter ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }


                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Error setfilter : %s\n", pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }

                // Analyse des paquets
                pcap_loop(handle, -1, got_packet, NULL);


                pcap_freecode(&fp);
                pcap_close(handle);
        }
        else
        {
                //Offline
                printf("Offline capture \n ");
                printf("File: %s\n", fichier);

                handle = pcap_open_offline(fichier, errbuf);

                if (handle == NULL) {
                        fprintf(stderr, "Error pcap_open_offline (file : %s ) : %s\n", fichier, errbuf);
                        return -1;
                }

                if ( fflag == 1 )
                {
                        if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
                                fprintf(stderr, "Error filter ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }
                else {
                        if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
                                fprintf(stderr, "Error filter ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }

                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Error setfilter : %s\n", pcap_geterr(handle));
                        return -1;
                }

                // Analyse des paquets
                pcap_loop(handle, -1, got_packet, NULL);


                pcap_freecode(&fp);
                pcap_close(handle);

        }
        printf("\nCapture complete.\n");

        return 0;
}
