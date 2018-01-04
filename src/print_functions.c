

#include "../include/print_functions.h"

/*
 * print packet payload data (avoid printing binary data)
 */
void print_ftp(const u_char *payload, int len)
{
        int i;
        const u_char *ch = payload;

        /* ascii (if printable) */
        ch = payload;
        printf("    ");
        for(i = 0; i < len; i++) {
                if ( (*ch == 0xd) && (*ch+1 == 0xa))
                        printf("\n    ");
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
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
        printf("   Sequence number : %d \n", (u_int)tcp->th_seq); // NOT OK
        printf("   Acknowledgement number : %d \n", ntohl((u_int)tcp->th_ack)); // NOT OK
        printf("   Header Length : %d bytes \n",tcp->th_off*4);
        printf("   Flags : %#06x \n",tcp->th_flags);
        printf("   Window size value : %d \n",__builtin_bswap16(tcp->th_win));
        printf("   Checksum : %#06x \n",__builtin_bswap16(tcp->th_sum));
        printf("   Urgent pointer : %d \n",tcp->th_urp);


}

void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet)
{
        const char *payload;        /* Packet payload */
        int size_tcp = tcp->th_off*4;
        int size_payload;

        if ( tcp_len > 0 )
        {
                if ( ntohs(tcp->th_sport) == 25 || ntohs(tcp->th_dport) == 25 ) {
                        printf("   SMTP \n");
                }
                else if (  ntohs(tcp->th_sport) == 143 || ntohs(tcp->th_dport) == 143 ) {
                        printf("   IMAP \n");
                }
                else if (  ntohs(tcp->th_sport) == 110 || ntohs(tcp->th_dport) == 110 ) {
                        printf("   POP \n");
                }
                else if (  ntohs(tcp->th_sport) == 23 || ntohs(tcp->th_dport) == 23 ) {
                        printf("   TELNET \n");
                }
                else if (  ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ) {
                        printf("\n Hypertext Transfer Protocol (HTTP) \n");
                }
                else if (  ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) == 21 || ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) == 20 ) {
                        printf("\n File Transfer Protocol (FTP) \n");
                }
                else {
                        printf("\n Unknown protocol\n");
                }
        }

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + size_tcp);
        size_payload = ip_tot_len - (size_ip + size_tcp);

        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                print_ftp(payload, size_payload);
        }
}

void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet){
        const char *payload;  /* Packet payload */
        int size_payload;

        if (  ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53 ) {

                printf("\n DNS \n");
        }
        else if (( ntohs(udp->uh_sport) == 67 && ntohs(udp->uh_dport) == 68 ) || ( ntohs(udp->uh_sport) == 68 && ntohs(udp->uh_dport) == 67 )) {

                printf("\n Bootstrap Protocol \n");
        }
        else {
                printf("\n Unknown protocol\n");
        }

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + sizeof(udp));

        /* compute tcp payload (segment) size */
        size_payload = ip_tot_len - (size_ip + sizeof(udp));

        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
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
