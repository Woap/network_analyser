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
// BOOTP / DHCP DEF OK
// DNS DEF
// SMTP OK
// POP ? OK
// IMAP OK
// SCTP ?
// HTTP OK
// FTP OK
// TELNET OK


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* verbosite */
int verbosite = 0;

struct my_arphdr {
        u_int16_t ar_hrd; /* Hardware Type           */
        u_int16_t ar_pro; /* Protocol Type           */
        u_char ar_hln;    /* Hardware Address Length */
        u_char ar_pln;    /* Protocol Address Length */
        u_int16_t ar_op; /* Operation Code          */
        u_char ar_sha[6];  /* Sender Mac address */
        u_char ar_sip[4];  /* Sender IP address       */
        u_char ar_tha[6];  /* Target Mac address */
        u_char ar_tip[4];  /* Target IP address       */
};

void print_dns(const u_char *payload, int len)
{
        const struct dns_header *dns; /* The IP header */
        dns = (struct dns_header*)(payload);


        printf("Transaction ID : %#03x\n",__builtin_bswap16(dns->id));
        printf("Flags : %#03x\n",__builtin_bswap16(dns->flags));
        printf("Questions: %d\n",__builtin_bswap16(dns->questions));
        printf("Answer RRs: %d\n",__builtin_bswap16(dns->answer));
        printf("Authority RRs: %d\n",__builtin_bswap16(dns->authority));
        printf("Additional RRs: %d\n",__builtin_bswap16(dns->additional));
        printf("Queries\n");

}


void print_bootp(const u_char *payload, int len)
{

        const struct bootp *bootp;  /* The IP header */
        bootp = (struct bootp*)(payload);
        if ( bootp->bp_op == 1)
                printf("Message type : Boot Request (%u)\n",bootp->bp_op);
        else
                printf("Message type : Boot Reply (%u)\n",bootp->bp_op);

        switch (bootp->bp_htype) {
        case HTYPE_ETHERNET: printf("Hardware type : Ethernet (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_EXP_ETHERNET: printf("Hardware type : Exp_ethernet (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_AX25: printf("Hardware type : AX25 (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_PRONET: printf("Hardware type : Pronet (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_CHAOS: printf("Hardware type : Chaos (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_IEEE802: printf("Hardware type : IEEE802 (%#03x)\n",bootp->bp_htype); break;
        case HTYPE_ARCNET: printf("Hardware type : ArcNet (%#03x)\n",bootp->bp_htype); break;
        default:
                printf("Hardware type : Unknown (%#03x)\n",bootp->bp_htype); break;
        }

        printf("Hardware address length : %u\n",bootp->bp_hlen);
        printf("Hops : %u\n",bootp->bp_hops);
        printf("Transaction ID : %#10x\n",__builtin_bswap32(bootp->bp_xid));
        printf("Seconds elapsed : %u\n",bootp->bp_secs);
        printf("Bootp flags : %u (Unicast)\n",bootp->bp_flags);
        printf("Client IP address : %s\n",inet_ntoa(bootp->bp_ciaddr));
        printf("Client IP address : %s\n",inet_ntoa(bootp->bp_yiaddr));
        printf("Next server IP address : %s\n",inet_ntoa(bootp->bp_siaddr));
        printf("Relay agent IP address : %s\n",inet_ntoa(bootp->bp_giaddr));
        printf("Client MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",bootp->bp_chaddr[0],bootp->bp_chaddr[1],bootp->bp_chaddr[2],bootp->bp_chaddr[3],bootp->bp_chaddr[4],bootp->bp_chaddr[5]);
        printf("Server name option overloaded by DHCP : %s \n",bootp->bp_sname);
        printf("Boot file name option overloaded by DHCP : %s \n", bootp->bp_file);

}

void print_telnet(const u_char *payload, int len)
{

        int i;
        int end_flag=0;
        const u_char *ch = payload;

        /* ascii (if printable) */
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

                        if ( *ch != 255 && i+3 != len)
                        {
                                printf("      Option data : " );
                                while ( *ch != 255 && i < len)
                                {
                                        printf("%02x ", *ch);
                                        ch++;
                                        i++;

                                }
                                printf("\n");

                        }
                }

                end_flag=0;




        }

        printf("\n\n");
        return;

}


void print_ftp_http_imap_smtp_pop(const u_char *payload, int len)
{
        int i;
        const u_char *ch = payload;

        /* ascii (if printable) */
        ch = payload;
        printf("    ");
        int cnt = 0;
        for(i = 0; i < len; i++) {

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
                                printf("\n    ");
                                cnt=0;
                        }

                }
                ch++;
        }

        printf("\n\n");
        return;

}


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

        int i;
        int gap;
        const u_char *ch;

        /* offset */
        printf("        %05d   ", offset);

        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
                printf("%02x ", *ch);
                ch++;
                /* print extra space after 8th byte for visual aid */
                if (i == 7)
                        printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
                printf(" ");

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        printf("   ");
                }
        }
        printf("   ");

        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n");

        return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

        int len_rem = len;
        int line_width = 16; /* number of bytes per line */
        int line_len;
        int offset = 0;   /* zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
                return;

        /* data fits on one line */
        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset);
                return;
        }

        /* data spans multiple lines */
        for (;; ) {
                /* compute current line length */
                line_len = line_width % len_rem;
                /* print line */
                print_hex_ascii_line(ch, line_len, offset);
                /* compute total remaining */
                len_rem = len_rem - line_len;
                /* shift pointer to remaining bytes to print */
                ch = ch + line_len;
                /* add offset */
                offset = offset + line_width;
                /* check if we have line width chars or less */
                if (len_rem <= line_width) {
                        /* print last line and get out */
                        print_hex_ascii_line(ch, len_rem, offset);
                        break;
                }
        }

        return;
}

void print_ethernetheader(const struct ether_header *ethernet)
{
        printf("   Destination : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]); // NOT OK
        printf("   Source : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]); // NOT OK

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
                //  printf("    Flags : %#06x \n",);
                printf("   Fragment offset : %d \n",ip->frag_off); // NOT OK
                printf("   Time to live : %d\n",ip->ttl);
                printf("   Header checksum : %#06x \n",__builtin_bswap16(ip->check));

                printf("   Source : %s\n", inet_ntoa(srce_addr));
                printf("   Destination : %s\n", inet_ntoa(dsti_addr));
        }

}

void print_tcpheader(const struct tcphdr *tcp,int tcp_len)
{

        /* define/compute tcp header offset */
        // TOT LEN IP - ip hdr - tcp hdr

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
                        printf("\n Simple Mail Transfer Protocol (SMTP) \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 143 || ntohs(tcp->th_dport) == 143 ) {
                        printf("\n IMAP \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 110 || ntohs(tcp->th_dport) == 110 ) {
                        printf("\n POP \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 23 || ntohs(tcp->th_dport) == 23 ) {
                        printf("\n Telnet \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_telnet(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ) {
                        printf("\n Hypertext Transfer Protocol (HTTP) \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) == 21 || ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) == 20 ) {
                        printf("\n File Transfer Protocol (FTP) \n");
                        if (size_payload > 0) {
                                printf("   Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload);
                        }
                }
                else {
                        printf("\n Unknown protocol\n");
                }
        }



}

void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet){
        const u_char *payload;  /* Packet payload */
        int size_payload;

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + sizeof(udp));
        size_payload = ip_tot_len - (size_ip + sizeof(udp));

        if (  ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53 ) {

                printf("\n DNS \n");
                if (size_payload > 0) {
                        printf("   Payload (%d bytes):\n", size_payload);
                        print_dns(payload, size_payload);
                        printf("---\n");
                        print_payload(payload, size_payload);
                }
        }
        else if (( ntohs(udp->uh_sport) == 67 && ntohs(udp->uh_dport) == 68 ) || ( ntohs(udp->uh_sport) == 68 && ntohs(udp->uh_dport) == 67 )) {

                printf("\n Bootstrap Protocol \n");
                if (size_payload > 0) {
                        printf("   Payload (%d bytes):\n", size_payload);
                        print_bootp(payload, size_payload);
                }
        }
        else {
                printf("\n Unknown protocol\n");
        }




}

void print_udpheader(const struct udphdr *udp)
{

        printf("   Source port: %d\n", ntohs(udp->uh_sport));
        printf("   Destination port: %d\n", ntohs(udp->uh_dport));
        printf("   Length: %d\n", ntohs(udp->uh_ulen));
        printf("   Checksum: %#06x\n",__builtin_bswap16(udp->uh_sum));

}

void print_arpheader(const struct my_arphdr *arp)
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



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

        static int count = 1;

        const struct ether_header *ethernet; /* The ethernet header [1] */
        const struct iphdr *ip;        /* The IP header */
        const struct tcphdr *tcp;      /* The TCP header */
        const struct udphdr *udp;        /* The UDP header */
        const struct my_arphdr *arp;      /* The TCP header */
        const u_char *payload;              /* Packet payload */

        int size_ip;
        int size_tcp;


        int size_payload;

        printf("\n-------------------------------------\n");
        printf("\nPacket number %d:\n", count);
        count++;


        ethernet = (struct ether_header*)(packet);

        if ( verbosite >= 2 )
        { printf(" Ethernet II, ");
          printf("Src: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
          printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]); }
        if ( verbosite == 3 ) print_ethernetheader(ethernet);

        switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_IP:

                if ( verbosite == 3 ) printf("   Type : IPv4 (%#06x) \n", ntohs(ethernet->ether_type));
                ip = (struct iphdr*)(packet + sizeof(struct ether_header));
                size_ip = ip->ihl*4;

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

                        // OPT

                        int option_size;
                        const u_char *payload;                /* Packet payload */
                        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + 20);

                        option_size = tcp->th_off*4 - 20;

                        const u_char *ch = payload;

                        /* ascii (if printable) */
                        ch = payload;
                        if ( option_size > 0 )
                        {
                                printf("   Options : (%d bytes)\n",option_size);

                                for ( int i = 0; i < option_size; i++)
                                {

                                        /*if (isprint(*ch))

                                           else
                                           {
                                                printf(".");
                                           }*/
                                        switch (*ch) {
                                        case TCPOPT_EOL: printf( "   End of option list \n"); break;
                                        case TCPOPT_NOP: printf( "   No operation (NOP) \n"); break;
                                        case TCPOPT_MAXSEG: printf( "   Maximum segment size "); break;
                                        case TCPOPT_WINDOW: printf( "   Window Scale	 "); break;
                                        case TCPOPT_SACK_PERMITTED: printf( "   SACK Permitted "); break;
                                        case TCPOPT_SACK: printf( "   SACK "); break;
                                        case TCPOPT_TIMESTAMP:
                                                printf( "   Timestamps ");

                                                break;
                                        case TCPOLEN_TIMESTAMP: printf( "   AO "); break;
                                        case TCPOLEN_TSTAMP_APPA: printf( "   IP "); break;
                                        default:
                                                printf("UNKNOWN ");

                                        }

                                        ch++;

                                }
                                printf("\n");

                        }

                        if ( verbosite == 3 ) print_tcppayload(tcp,tcp_len,size_ip,ntohs(ip->tot_len),packet);

                        return;
                case IPPROTO_UDP:

                        if ( verbosite == 3 ) printf("   Protocol: UDP (%d)\n",ip->protocol);
                        udp = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);



                        if ( verbosite >= 2 ) printf("\n User Datagram Protocol, Src Port: %d, Dst Port: %d \n",ntohs(udp->uh_sport),ntohs(udp->uh_dport));
                        if ( verbosite == 3 ) print_udpheader(udp);
                        if ( verbosite == 3 ) print_udppayload(udp,size_ip,ntohs(ip->tot_len),packet);

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

                if ( verbosite == 3 ) printf("   Type : ARP (%#06x) \n", ntohs(ethernet->ether_type));

                payload = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct my_arphdr));
                size_payload = 60 - (sizeof(struct ether_header) + sizeof(struct my_arphdr));

                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   Padding (%d bytes) :\n", size_payload);
                        if ( verbosite == 3 ) print_payload(payload, size_payload);
                }

                if ( verbosite >= 2 ) printf("\n Address Resolution Protocol \n");
                arp = (struct my_arphdr*)(packet + sizeof(struct ether_header));

                if ( verbosite == 3 ) print_arpheader(arp);

                break;
        case ETHERTYPE_REVARP:
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

        // ARGUMENT
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


        char *dev = NULL; /* capture device name */
        char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
        pcap_t *handle; /* packet capture handle */

        char filter_exp[] = "ip"; /* filter expression [3] */
        struct bpf_program fp; /* compiled filter program (expression) */
        bpf_u_int32 mask; /* subnet mask */
        bpf_u_int32 net; /* ip */
        int num_packets = 10; /* number of packets to capture */



        //get network number and mask associated with capture device
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                        dev, errbuf);
                net = 0;
                mask = 0;
        }

        /* print capture info */
        printf("Device: %s\n", interface);
        printf("Number of packets: %d\n", num_packets);

        if ( fflag == 1)
                printf("Filter expression: %s\n", filtre);

        // Online
        /* open capture device */
        if ( iflag == 1 )
        {
                handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
                if (handle == NULL) {
                        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
                        exit(EXIT_FAILURE);
                }

                if (pcap_datalink(handle) != DLT_EN10MB) {
                        fprintf(stderr, "%s is not an Ethernet\n", interface);
                        exit(EXIT_FAILURE);
                }


                if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                                filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }


                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Couldn't install filter %s: %s\n",
                                filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }


                pcap_loop(handle, num_packets, got_packet, NULL);


                pcap_freecode(&fp);
                pcap_close(handle);
        }
        else
        {


                //Offline
                handle = pcap_open_offline(fichier, errbuf);

                if (handle == NULL) {
                        fprintf(stderr, "Erreur pcap_open_offline (file : %s ) : %s\n", fichier, errbuf);
                        return -1;
                }

                if ( fflag == 1 )
                {
                        if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
                                fprintf(stderr, "Erreur filtre expression ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }
                else {
                        if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
                                fprintf(stderr, "Erreur filtre expression ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }

                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Erreur pcap_setfilter : %s\n", pcap_geterr(handle));
                        return -1;
                }

                // Analyse des paquets
                pcap_loop(handle, num_packets, got_packet, NULL);

        }
        printf("\nCapture complete.\n");

        return 0;
}
