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

#include <netinet/ip.h> // ip OK
#include <netinet/udp.h> // UDP OK
#include <netinet/tcp.h> // TCP OK
#include <net/if_arp.h> // OK
#include "../include/bootp.h" // OK
#include "../include/dns.h" // OK
#include "../include/arp.h"
// BOOTP / DHCP DEF OK
// DNS DEF
// SMTP OK
// POP ? OK
// IMAP OK
// SCTP ?
// HTTP OK
// FTP OK
// TELNET OK


typedef enum { FTP, HTTP, IMAP, SMTP, POP} protocol_app;

int paquet_count;
struct in_addr paquet_srcaddr;
struct in_addr paquet_dstaddr;
int paquet_length;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* verbosite */
int verbosite = 0;

void print_payload(const u_char *payload, int len);


void print_tcpoptions(const struct tcphdr *tcp, int size_ip,const u_char * packet)
{

        int option_size;
        const u_char *payload;
        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + 20);
        option_size = tcp->th_off*4 - 20;

        const u_char *ch = payload;
        int eol=0;

        ch = payload;
        if ( option_size > 0 )
        {
                printf("   Options : (%d bytes),",option_size);

                for ( int i = 0; i < option_size; i++)
                {
                        switch (*ch) {
                        case TCPOPT_EOL: printf( " End of option list \n"); break;
                        case TCPOPT_NOP: printf( " No operation (NOP),"); eol=1; break;
                        case TCPOPT_MAXSEG: printf( " Maximum segment size,"); break;
                        case TCPOPT_WINDOW: printf( " Window Scale,"); break;
                        case TCPOPT_SACK_PERMITTED: printf( " SACK Permitted,"); break;
                        case TCPOPT_TIMESTAMP: printf(" Timestamps,"); break;
                        case TCPOLEN_TIMESTAMP: printf( " Timestamps,"); break;
                        case TCPOLEN_TSTAMP_APPA: printf( "   IP "); break;
                        default:
                                printf("UNKNOWN, ");
                        }

                        if ( eol == 0)
                        {
                                ch++;
                                int len = (u_int8_t)*ch;
                                len = len - 2;

                                ch++;
                                i++;
                                for ( int j = 0; j < len; j++)
                                {
                                        i++;
                                        ch++;
                                }
                                ch--;
                        }
                        eol=0;
                        ch++;
                }
                printf("\n");
        }
}

void print_dns(const u_char *payload, int len)
{
        const struct dns_header *dns; /* The IP header */
        dns = (struct dns_header*)(payload);

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", paquet_count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                if ( 0x8180 == __builtin_bswap16(dns->flags))
                {
                        printf(" - Protocol : DNS - Length : %d - Info : Standart query response - Transaction ID %#03x \n",paquet_length,__builtin_bswap16(dns->id));
                }
                if ( 0x0100 == __builtin_bswap16(dns->flags))
                {
                        printf(" - Protocol : DNS - Length : %d - Info : Standart query - Transaction ID %#03x \n",paquet_length,__builtin_bswap16(dns->id));
                }
        }

        if ( verbosite == 3)
        {
                printf("   Transaction ID : %#03x\n",__builtin_bswap16(dns->id));

                printf("   Flags : %#03x ",__builtin_bswap16(dns->flags));
                if ( 0x8180 == __builtin_bswap16(dns->flags))
                {
                        printf("Standard Query Response \n");
                }
                if ( 0x0100 == __builtin_bswap16(dns->flags))
                {
                        printf("Standard Query \n");
                }
                printf("   Questions: %d\n",__builtin_bswap16(dns->questions));
                printf("   Answer RRs: %d\n",__builtin_bswap16(dns->answer));
                printf("   Authority RRs: %d\n",__builtin_bswap16(dns->authority));
                printf("   Additional RRs: %d\n",__builtin_bswap16(dns->additional));
                printf("   Queries\n");


                //const u_char *queries_answers;
                //queries_answers = (u_char *)(payload+ sizeof(struct dns_header));

                printf("   ---\n");
                //print_payload(queries_answers, len-sizeof(struct dns_header));
                printf("   ---\n");
        }

}


void print_bootp(const u_char *payload, int len)
{

        const struct bootp *bootp;
        bootp = (struct bootp*)(payload);

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", paquet_count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                printf(" - Protocol : BOOTP/DHCP - Length : %d - Info : DHCP Discover - Transaction ID %#10x \n",paquet_length,__builtin_bswap32(bootp->bp_xid));
        }
        if ( verbosite == 3)
        {
                if ( bootp->bp_op == 1)
                        printf("   Message type : Boot Request (%u)\n",bootp->bp_op);
                else
                        printf("   Message type : Boot Reply (%u)\n",bootp->bp_op);

                switch (bootp->bp_htype) {
                case HTYPE_ETHERNET: printf("   Hardware type : Ethernet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_EXP_ETHERNET: printf("   Hardware type : Exp_ethernet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_AX25: printf("   Hardware type : AX25 (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_PRONET: printf("   Hardware type : Pronet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_CHAOS: printf("   Hardware type : Chaos (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_IEEE802: printf("   Hardware type : IEEE802 (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_ARCNET: printf("   Hardware type : ArcNet (%#03x)\n",bootp->bp_htype); break;
                default:
                        printf("   Hardware type : Unknown (%#03x)\n",bootp->bp_htype); break;
                }

                printf("   Hardware address length : %u\n",bootp->bp_hlen);
                printf("   Hops : %u\n",bootp->bp_hops);
                printf("   Transaction ID : %#10x\n",__builtin_bswap32(bootp->bp_xid));
                printf("   Seconds elapsed : %u\n",bootp->bp_secs);
                printf("   Bootp flags : %u (Unicast)\n",bootp->bp_flags);
                printf("   Client IP address : %s\n",inet_ntoa(bootp->bp_ciaddr));
                printf("   Client IP address : %s\n",inet_ntoa(bootp->bp_yiaddr));
                printf("   Next server IP address : %s\n",inet_ntoa(bootp->bp_siaddr));
                printf("   Relay agent IP address : %s\n",inet_ntoa(bootp->bp_giaddr));
                printf("   Client MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",bootp->bp_chaddr[0],bootp->bp_chaddr[1],bootp->bp_chaddr[2],bootp->bp_chaddr[3],bootp->bp_chaddr[4],bootp->bp_chaddr[5]);
                printf("   Server name option overloaded by DHCP : %s \n",bootp->bp_sname);
                printf("   Boot file name option overloaded by DHCP : %s \n", bootp->bp_file);
                printf("   Magic Cookie : (%02x%02x%02x%02x) DHCP \n", bootp->bp_vend[0],bootp->bp_vend[1],bootp->bp_vend[2],bootp->bp_vend[3]);

                // OPT
                // SIZE 290 - 8 ( UDP ) - 236 ( BOOTP )    46 options
                int option_size;
                const u_char *vendor;
                vendor = (u_char *)(bootp->bp_vend+4);
                option_size = len-236-4;

                const u_char *ch = vendor;
                int eol=0;

                if ( option_size > 0 )
                {
                        for ( int i = 0; i < option_size; i++)
                        {
                                switch ((int)*ch) {
                                case 51: printf( "    Option: (%d) Ip Address Lease Time \n",*ch); break;
                                case 52: printf( "    Option: (%d) Option overload \n",*ch); break;
                                case 53: printf( "    Option: (%d) Message Type \n",*ch); break;
                                case 54: printf( "    Option: (%d) Server ID \n",*ch); break;
                                case 55: printf( "    Option: (%d) Parameter List \n",*ch); break;
                                case 56: printf( "    Option: (%d)  Message \n",*ch); break;
                                case 57: printf( "    Option: (%d) Max Msg Size\n",*ch); break;
                                case 58: printf( "    Option: (%d) Renewal Time \n",*ch); break;
                                case 59: printf( "    Option: (%d) Rebinding Time \n",*ch); break;
                                case 60: printf( "    Option: (%d) Class ID \n",*ch); break;
                                case 61: printf( "    Option: (%d) Client ID \n",*ch); break;
                                case 12: printf( "    Option: (%d) Hostname \n",*ch); break;
                                case 255: printf( "    Option: (%d) End \n",*ch); eol=1; break;
                                case 0: printf( "    Option: (%d) Padding \n",*ch); eol=1; break;
                                default:
                                        printf("    Option: (%d) Unknown \n",*ch);
                                        break;
                                }

                                if ( eol == 0)
                                {
                                        ch++;
                                        int len = (int)*ch;
                                        ch++;
                                        i++;
                                        for ( int j = 0; j < len; j++)
                                        {
                                                i++;
                                                ch++;
                                        }
                                        ch--;
                                }
                                eol=0;
                                ch++;
                        }
                        printf("\n");
                }
        }
}

void print_telnet(const u_char *payload, int len)
{
        int i;
        int end_flag=0;
        const u_char *ch = payload;

        ch = payload;

        for(i = 0; i < len; i=i+3) {
                printf("    ");
                ch++;
                switch (*ch) {
                case 255: printf( "-- "); break;
                case 254: printf( "DONT "); break;
                case 253: printf( "DO "); break;
                case 252: printf( "WONT "); break;
                case 251: printf( "WILL "); break;
                case 250: printf( "SUBOPTION "); break;
                case 249: printf( "GA "); break;
                case 248: printf( "EL "); break;
                case 247: printf( "EC "); break;
                case 246: printf( "AYT "); break;
                case 245: printf( "AO "); break;
                case 244: printf( "IP "); break;
                case 243: printf( "BREAK "); break;
                case 242: printf( "DM "); break;
                case 241: printf( "NOP "); break;
                case 240: printf( "SUBOPTION-END \n"); end_flag=1; i=i-1; break;
                case 239: printf( "EOR "); break;
                case 238: printf( "ABORT "); break;
                case 237: printf( "SUSP "); break;
                case 236: printf( "xEOF "); break;
                default:
                        printf("UNKNOWN ");

                }
                ch++;

                if ( end_flag != 1 )
                {

                        switch (*ch) {
                        case 00: printf( "TRANSMIT-BINARY\n"); break;
                        case 1: printf( "ECHO\n"); break;
                        case 3: printf( "SUPPRESS-GO-AHEAD\n"); break;
                        case 5: printf( "STATUS\n"); break;
                        case 6: printf( "TIMING-MARK\n"); break;
                        case 10: printf( "NEGOCIATE-ABOUT-OUTPUT-CARRIAGE-RETURN-DISPOSITION\n");  break;
                        case 11: printf( "NEGOCAITE-ABOUT-OUTPUT-HORIZONTAL-TABSTOPS\n"); break;
                        case 12: printf( "NEGOCIATE-ABOUT-OUTPUT-HORIZONTAL-DISPOSITION\n"); break;
                        case 13: printf( "NEGOCIATE-ABOUT-FORMFEED-DISPOSITION\n"); break;
                        case 14: printf( "NEGOCIATE-ABOUT-OUTPUT-VERTICAL-TABSTOPS\n"); break;
                        case 15: printf( "NEGOCIATE-ABOUT-OUTPUT-VERTICAL-TAB-DISPOSITION\n"); break;
                        case 16: printf( "NEGOCIATE-ABOUT-OUTPUT-LINEFEED-DISPOSITION\n"); break;
                        case 17: printf( "EXTEND-ASCII\n"); break;
                        case 18: printf( "LOGOUT\n"); break;
                        case 19: printf( "BYTE-MACRO\n"); break;
                        case 20: printf( "DATA-ENTRY-TERMINAL\n"); break;
                        case 23: printf( "SEND-LOCATION\n");  break;
                        case 24: printf( "TERMINAL-TYPE\n"); break;
                        case 25: printf( "END-OF-RECORD\n"); break;
                        case 26: printf( "TUID\n"); break;
                        case 27: printf( "OUTMRK\n"); break;
                        case 28: printf( "TTYLOC\n"); break;
                        case 29: printf( "3270-REGIME\n"); break;
                        case 30: printf( "X.3-PAD\n"); break;
                        case 31: printf( "NEGOCIAtE-ABOUT-WINDOW-SIZE\n"); break;
                        case 32: printf( "TERMINAL-SPEED\n"); break;
                        case 33: printf( "TOGGLE-FLOW-CONTROL\n"); break;
                        case 34: printf( "LINEMODE\n"); break;
                        case 35: printf( "X-DISPLAY LOCATION\n"); break;
                        case 36: printf( "ENVIRON\n"); break;
                        case 37: printf( "AUTHENTIFICATION\n"); break;
                        case 38: printf( "ENCRYPT\n"); break;
                        case 39: printf( "NEW-ENVIRON\n"); break;
                        case 40: printf( "TN3270E\n"); break;
                        case 42: printf( "CHARSET\n"); break;
                        case 44: printf( "COM-PORT OPTION\n"); break;
                        case 47: printf( "KERMIT\n"); break;

                        default:
                                printf("UNKNOWN\n ");
                        }
                        ch++;
                        int j =0;

                        if ( *ch != 255 && i+3 != len)
                        {
                                printf("      Option data : \n      " );
                                while ( *ch != 255 && i < len)
                                {
                                        printf("%02x ", *ch);
                                        ch++;
                                        i++;
                                        j++;
                                        if ( j%16 == 0) printf("\n      ");
                                }
                                printf("\n");
                        }
                }
                end_flag=0;
        }
        printf("\n");
        return;

}


void print_ftp_http_imap_smtp_pop(const u_char *payload, int len,protocol_app p)
{
        int i;
        const u_char *ch = payload;

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", paquet_count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                switch (p) {
                case FTP:
                        printf("- Protocol : FTP - Length : %d - Info : ",paquet_length);
                        break;
                case HTTP:
                        printf("- Protocol : HTTP - Length : %d - Info : ",paquet_length);
                        break;
                case IMAP:
                        printf("- Protocol : IMAP - Length : %d - Info : ",paquet_length);
                        break;
                case SMTP:
                        printf("- Protocol : SMTP - Length : %d - Info : ",paquet_length);
                        break;
                case POP:
                        printf("- Protocol : POP - Length : %d - Info : ",paquet_length);
                        break;
                default:
                        printf("- Protocol : UNKNOWN - Length : %d - Info : ",paquet_length);
                        break;
                }

        }

        if ( verbosite == 3 )
        {
                ch = payload;
                printf("    ");
                int cnt = 0;
                int firstline = 0;
                for(i = 0; i < len; i++) {
                        if ( firstline == 0)
                        {
                                if (isprint(*ch))
                                        printf("%c", *ch);
                                else
                                {
                                        if (*ch ==  0xd)
                                                cnt++;
                                        if (*ch ==  0xa)
                                                cnt++;
                                        if ( cnt == 2)
                                        {
                                                firstline =1;
                                                printf("\n    ");
                                                cnt=0;
                                        }
                                }
                                ch++;
                        }
                }
                printf("\n");
        }

        if ( verbosite == 1 )
        {
                ch = payload;
                int cnt = 0;
                int firstline = 0;
                for(i = 0; i < len; i++) {
                        if ( firstline == 0)
                        {
                                if (isprint(*ch))
                                        printf("%c", *ch);
                                else
                                {
                                        if (*ch ==  0xd)
                                                cnt++;

                                        if (*ch ==  0xa)
                                                cnt++;
                                        if ( cnt == 2)
                                        {

                                                firstline =1;
                                                printf("\n");
                                                cnt=0;
                                        }
                                }
                                ch++;
                        }
                }
        }
        return;
}


void print_ethernetheader(const struct ether_header *ethernet)
{
        printf("   Destination : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
        printf("   Source : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
}

void print_ipheader(const struct iphdr *ip)
{
        int size_ip;
        size_ip = ip->ihl*4;
        struct in_addr srce_addr;
        srce_addr.s_addr = ip->saddr;
        struct in_addr dsti_addr;
        dsti_addr.s_addr = ip->daddr;


        if ( verbosite >= 2 ) printf("Src : %s, ", inet_ntoa(srce_addr));
        if ( verbosite >= 2 ) printf("Dst : %s\n", inet_ntoa(dsti_addr));
        if ( verbosite == 3 )
        {
                printf("   Version : %d \n",ip->version);
                printf("   Header Length : %d bytes (%d) \n",size_ip,ip->ihl);
                printf("   Differentiated Services Field : %#04x \n",ip->tos );
                printf("   Total Length : %d \n",__builtin_bswap16(ip->tot_len));
                printf("   Identification : %#06x (%d) \n",__builtin_bswap16(ip->id), __builtin_bswap16(ip->id));
                printf("   Fragment offset : %d \n",ip->frag_off); // NOT OK
                printf("   Time to live : %d\n",ip->ttl);
                printf("   Header checksum : %#06x \n",__builtin_bswap16(ip->check));

                printf("   Source : %s\n", inet_ntoa(srce_addr));
                printf("   Destination : %s\n", inet_ntoa(dsti_addr));
        }

}

void print_tcpheader(const struct tcphdr *tcp,int tcp_len)
{

        printf("   Source port: %d\n", ntohs(tcp->th_sport));
        printf("   Destination port: %d\n", ntohs(tcp->th_dport));
        printf("   Sequence number : %d \n", ntohs(tcp->th_seq)); // NOT OK
        printf("   Acknowledgement number : %d \n",ntohs(tcp->th_ack)); // NOT OK
        printf("   Header Length : %d bytes \n",tcp->th_off*4);

        printf("   Flags : %#05x ( ",tcp->th_flags);
        if (tcp->th_flags & TH_URG) {
                printf("URG ");
        }
        if (tcp->th_flags & TH_ACK) {
                printf("ACK ");
        }
        if (tcp->th_flags & TH_PUSH) {
                printf("PUSH ");
        }
        if (tcp->th_flags & TH_RST) {
                printf("RST ");
        }
        if (tcp->th_flags & TH_SYN) {
                printf("SYN ");
        }
        if (tcp->th_flags & TH_FIN) {
                printf("FIN ");
        }
        printf(")\n");
        printf("   Window size value : %d \n",__builtin_bswap16(tcp->th_win));
        printf("   Checksum : %#06x \n",__builtin_bswap16(tcp->th_sum));
        printf("   Urgent pointer : %d \n",tcp->th_urp);

}


void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet)
{
        const u_char *payload;        /* Packet payload */
        int size_tcp = tcp->th_off*4;
        int size_payload;

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + size_tcp);
        size_payload = ip_tot_len - (size_ip + size_tcp);

        if ( tcp_len > 0 )
        {
                if ( ntohs(tcp->th_sport) == 25 || ntohs(tcp->th_dport) == 25 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : Simple Mail Transfer Protocol (SMTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,SMTP);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 143 || ntohs(tcp->th_dport) == 143 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : IMAP \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,IMAP);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 110 || ntohs(tcp->th_dport) == 110 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : POP \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,POP);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 23 || ntohs(tcp->th_dport) == 23 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : Telnet \n");
                        if ( verbosite ==1 )
                        {
                                printf("# Packet number %d - ", paquet_count);
                                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                                printf("- Protocol : TELNET - Length : %d - Info : Telnet Data ..\n",paquet_length);
                        }
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                if ( verbosite == 3 ) print_telnet(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : Hypertext Transfer Protocol (HTTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,HTTP);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) == 21 || ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) == 20 ) {
                        if ( verbosite >= 2 ) printf("\n Application layer : File Transfer Protocol (FTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,FTP);
                        }
                }
                else {
                        if ( verbosite >= 2 ) printf("\n Application layer : Unknown protocol\n");
                }
        }
        else
        {
                if ( verbosite == 1 )
                {
                        printf("# Packet number %d - ", paquet_count);
                        printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                        printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                        printf("- Protocol : TCP - Length : %d - Info : %d -> %d [ ",paquet_length, ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                }
                if (tcp->th_flags & TH_URG) {
                        printf("URG ");
                }
                if (tcp->th_flags & TH_ACK) {
                        printf("ACK ");
                }
                if (tcp->th_flags & TH_PUSH) {
                        printf("PUSH ");
                }
                if (tcp->th_flags & TH_RST) {
                        printf("RST ");
                }
                if (tcp->th_flags & TH_SYN) {
                        printf("SYN ");
                }
                if (tcp->th_flags & TH_FIN) {
                        printf("FIN ");
                }
                printf ("]\n");
        }

}

void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet){
        const u_char *payload;  /* Packet payload */
        int size_payload;

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + sizeof(udp));
        size_payload = ip_tot_len - (size_ip + sizeof(udp));

        if (  ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53 ) {

                if ( verbosite >= 2 ) printf("\n Application layer : DNS \n");
                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                        print_dns(payload, size_payload);

                }
        }
        else if (( ntohs(udp->uh_sport) == 67 && ntohs(udp->uh_dport) == 68 ) || ( ntohs(udp->uh_sport) == 68 && ntohs(udp->uh_dport) == 67 )) {

                if ( verbosite >= 2 ) printf("\n Application layer: Bootstrap Protocol / DHCP \n");
                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   Payload (%d bytes):\n", size_payload);
                        print_bootp(payload, size_payload);
                }
        }
        else {
                printf("\n Unknown protocol (UDP)\n");
        }

}

void print_udpheader(const struct udphdr *udp)
{
        printf("   Source port: %d\n", ntohs(udp->uh_sport));
        printf("   Destination port: %d\n", ntohs(udp->uh_dport));
        printf("   Length: %d\n", ntohs(udp->uh_ulen));
        printf("   Checksum: %#06x\n",__builtin_bswap16(udp->uh_sum));

}

void print_arpheader(const struct my_arphdr *arp,const struct ether_header *ethernet )
{
        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", paquet_count);
                printf("Source: %02x:%02x:%02x:%02x:%02x:%02x - ", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                printf("- Protocol : ARP - Length : %d - Info : Who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n",paquet_length,arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3],arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);
        }


        if ( verbosite == 3)
        {
                switch(ntohs(arp->ar_hrd)) {
                case ARPHRD_ETHER:
                        printf("   Hardware type: Ethernet (%d)\n",ntohs(arp->ar_hrd));
                        break;
                default:
                        printf("   Hardware type: unknown \n");
                        break;
                }

                switch(ntohs(arp->ar_pro)) {
                case ETH_P_IP:
                        printf("   Protocol type: IPv4 (%#06x)\n",ntohs(arp->ar_pro));
                        break;
                default:
                        printf("   Protocol type: unknown \n");
                        break;
                }

                printf("   Hardware size :  %u\n",arp->ar_hln);
                printf("   Protocol size: %u\n",arp->ar_pln);

                switch(ntohs(arp->ar_op)) {
                case ARPOP_REQUEST:
                        printf("   Opcode : ARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_REPLY:
                        printf("   Opcode : ARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_RREQUEST:
                        printf("   Opcode : RARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_RREPLY:
                        printf("   Opcode : RARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_InREQUEST:
                        printf("   Opcode : InARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_InREPLY:
                        printf("   Opcode : InARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_NAK:
                        printf("   Opcode : ARP NAK (%d)\n",ntohs(arp->ar_op));
                        break;
                default:
                        printf("   Opcode: unknown \n");
                        break;
                }

                printf("   Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_sha[0],arp->ar_sha[1],arp->ar_sha[2],arp->ar_sha[3],arp->ar_sha[4],arp->ar_sha[5]);
                printf("   Sender IP address: %d.%d.%d.%d\n",arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);

                printf("   Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_tha[0],arp->ar_tha[1],arp->ar_tha[2],arp->ar_tha[3],arp->ar_tha[4],arp->ar_tha[5]);
                printf("   Target IP address: %d.%d.%d.%d\n",arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3]);
        }

}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

        static int count = 1; // Numerotation paquets

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

        printf("-------------------------------------\n");

        switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_IP:
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
                if ( verbosite == 3 ) print_ethernetheader(ethernet);

                size_ip = ip->ihl*4;

                if ( verbosite == 3 ) printf("   Type : IPv4 (%#06x) \n", ntohs(ethernet->ether_type));
                if ( verbosite >= 2 ) printf("\n Internet Protocol Version 4, ");

                print_ipheader(ip);

                switch(ip->protocol ) {
                case IPPROTO_TCP:

                        if ( verbosite == 3 ) printf("   Protocol: TCP (%d)\n",ip->protocol);
                        tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
                        size_tcp = tcp->th_off*4;
                        int tcp_len = __builtin_bswap16(ip->tot_len)-size_ip-size_tcp;

                        if ( verbosite >= 2 ) printf("\n Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d \n",ntohs(tcp->th_sport),ntohs(tcp->th_dport),(u_int)tcp->th_seq,ntohl(tcp->th_ack),tcp_len);
                        if ( verbosite == 3 ) print_tcpheader(tcp,tcp_len);
                        if ( verbosite == 3 ) print_tcpoptions(tcp,size_ip,packet);

                        print_tcppayload(tcp,tcp_len,size_ip,ntohs(ip->tot_len),packet);

                        return;
                case IPPROTO_UDP:

                        udp = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);
                        if ( verbosite == 3 ) printf("   Protocol: UDP (%d)\n",ip->protocol);
                        if ( verbosite >= 2 ) printf("\n User Datagram Protocol, Src Port: %d, Dst Port: %d \n",ntohs(udp->uh_sport),ntohs(udp->uh_dport));
                        if ( verbosite == 3 ) print_udpheader(udp);
                        print_udppayload(udp,size_ip,ntohs(ip->tot_len),packet);
                        return;
                case IPPROTO_ICMP:

                        if ( verbosite == 3 ) printf("   Protocol: ICMP (%d)\n",ip->protocol);
                        return;
                case IPPROTO_IP:

                        if ( verbosite == 3 ) printf("   Protocol: IP (%d)\n",ip->protocol);
                        return;
                default:

                        if ( verbosite == 3 ) printf("   Protocol: unknown\n");
                        return;
                }
                break;

        case ETHERTYPE_ARP:

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
                if ( verbosite == 3 ) print_ethernetheader(ethernet);
                if ( verbosite == 3 ) printf("   Type : ARP (%#06x) \n", ntohs(ethernet->ether_type));

                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   Padding (%d bytes) \n", size_payload);
                }

                if ( verbosite >= 2 ) printf("\n Address Resolution Protocol \n");
                arp = (struct my_arphdr*)(packet + sizeof(struct ether_header));

                print_arpheader(arp,ethernet);

                break;
        case ETHERTYPE_REVARP:
                if ( verbosite == 3 ) printf("   Type : RARP (%#06x) \n", ntohs(ethernet->ether_type));
                break;
        default:
                if ( verbosite == 3 ) printf("   Type: unknown \n");

                break;
        }
        count++;
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
        int num_packets = 10;


        if ( fflag == 1)
                printf("Filter expression: %s\n", filtre);

        // Online
        // Configuration pcap
        if ( iflag == 1 )
        {
                printf("Live capture \n");
                printf("Interface: %s\n", interface);
                printf("Number of packets: %d\n", num_packets);
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
                pcap_loop(handle, num_packets, got_packet, NULL);


                pcap_freecode(&fp);
                pcap_close(handle);
        }
        else
        {
                //Offline
                printf("Offline capture \n ");
                printf("File: %s\n", fichier);
                printf("Number of packets: %d\n", num_packets);
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
                pcap_loop(handle, num_packets, got_packet, NULL);

        }
        printf("\nCapture complete.\n");

        return 0;
}
